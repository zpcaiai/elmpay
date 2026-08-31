package com.elmpay.webhook.delivery;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class WebhookDeliveryServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static final byte[] SECRET = "delivery-signing-secret-32-bytes!".getBytes(StandardCharsets.UTF_8);

    @Test
    void signingSecretContentTypeIsUniqueAndExact() {
        try (var exact = response(Map.of(
                "Content-Type", List.of("application/octet-stream")))) {
            assertDoesNotThrow(() -> HttpsWebhookSigningSecretResolver.requireContentType(
                    exact, "application/octet-stream"));
        }
        try (var duplicate = response(Map.of(
                "Content-Type", List.of("application/octet-stream", "text/plain")))) {
            assertThrows(SecurityException.class,
                    () -> HttpsWebhookSigningSecretResolver.requireContentType(
                            duplicate, "application/octet-stream"));
        }
        assertThrows(IllegalStateException.class,
                () -> HttpsWebhookSigningSecretResolver.fromEnvironment(Map.of(
                        "ELMPAY_WEBHOOK_SIGNING_SECRET_ACCESS_TOKEN", "inline-is-forbidden"),
                        Clock.systemUTC()));
    }

    private static com.elmpay.security.BoundedHttpTransport.Response response(
            Map<String, List<String>> headers) {
        return new com.elmpay.security.BoundedHttpTransport.Response(200,
                HttpHeaders.of(headers, (name, value) -> true), new byte[] {1});
    }

    @Test
    void signsAndMarksSuccessfulDelivery() throws Exception {
        WebhookDeliveryService.Delivery claimed = delivery(0, 3);
        FakeOutbox outbox = new FakeOutbox(claimed);
        AtomicReference<WebhookDeliveryService.OutboundRequest> sent = new AtomicReference<>();
        WebhookDeliveryService service = service(outbox, request -> {
            sent.set(request);
            return new WebhookDeliveryService.HttpResult(204, Map.of());
        }, InetAddress.getByName("8.8.8.8"));

        assertEquals(WebhookDeliveryService.Outcome.DELIVERED, service.deliverNext());
        assertEquals("DELIVERED", outbox.state);
        assertEquals("8.8.8.8", sent.get().target().addresses().getFirst().getHostAddress());
        assertEquals("hooks.example.test", sent.get().target().host());
        String timestamp = sent.get().headers().get("X-Elmpay-Timestamp");
        String supplied = sent.get().headers().get("X-Elmpay-Signature");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
        byte[] expected = mac.doFinal((timestamp + ".{\"event\":true}").getBytes(StandardCharsets.UTF_8));
        assertEquals("t=" + timestamp + ",v1="
                + Base64.getUrlEncoder().withoutPadding().encodeToString(expected), supplied);
        assertTrue(allZero(claimed.payload()));
        assertTrue(allZero(sent.get().body()));
        assertThrows(IllegalArgumentException.class,
                () -> new WebhookDeliveryService.HttpResult(700, Map.of()));
    }

    @Test
    void matchesTheCrossLanguageGoldenVector() {
        byte[] secret = Base64.getUrlDecoder().decode(
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc");
        byte[] payload = "{\"event\":\"payment.succeeded\",\"amount\":1250}"
                .getBytes(StandardCharsets.UTF_8);
        assertEquals("t=1787702400,v1=NgtUFKuSvOfNdb2InZjDTBS3axZlxKNnw1QLrb3elDw",
                WebhookDeliveryService.signingHeader(1_787_702_400L, secret, payload));
    }

    @Test
    void retryableFailureIsScheduledThenExhaustionMovesToDeadLetter() throws Exception {
        FakeOutbox retry = new FakeOutbox(delivery(0, 3));
        WebhookDeliveryService retryService = service(retry,
                request -> new WebhookDeliveryService.HttpResult(503, Map.of()),
                InetAddress.getByName("8.8.8.8"));
        assertEquals(WebhookDeliveryService.Outcome.RETRY_SCHEDULED, retryService.deliverNext());
        assertEquals("RETRY", retry.state);
        assertTrue(retry.nextAttemptAt.isAfter(NOW));

        FakeOutbox exhausted = new FakeOutbox(delivery(2, 3));
        WebhookDeliveryService exhaustedService = service(exhausted,
                request -> new WebhookDeliveryService.HttpResult(503, Map.of()),
                InetAddress.getByName("8.8.8.8"));
        assertEquals(WebhookDeliveryService.Outcome.DEAD_LETTERED, exhaustedService.deliverNext());
        assertEquals("DEAD", exhausted.state);
    }

    @Test
    void blocksDnsRebindingToLoopbackBeforeNetworkCall() throws Exception {
        FakeOutbox outbox = new FakeOutbox(delivery(0, 3));
        AtomicInteger calls = new AtomicInteger();
        WebhookDeliveryService service = service(outbox, request -> {
            calls.incrementAndGet();
            return new WebhookDeliveryService.HttpResult(204, Map.of());
        }, InetAddress.getByName("127.0.0.1"));
        assertEquals(WebhookDeliveryService.Outcome.DEAD_LETTERED, service.deliverNext());
        assertEquals(0, calls.get());
        assertEquals("SECURITY_POLICY", outbox.errorCode);
    }

    @Test
    void pinsTheValidatedAnswerAndRevalidatesDnsOnTheNextAttempt() throws Exception {
        AtomicInteger resolutions = new AtomicInteger();
        WebhookDeliveryService.EndpointPolicy policy = new WebhookDeliveryService.EndpointPolicy(
                Set.of("hooks.example.test"), host -> resolutions.getAndIncrement() == 0
                        ? new InetAddress[] {InetAddress.getByName("8.8.8.8")}
                        : new InetAddress[] {InetAddress.getByName("127.0.0.1")});
        URI endpoint = URI.create("https://hooks.example.test/payments");

        WebhookDeliveryService.EndpointPolicy.ValidatedEndpoint first = policy.validate(endpoint);

        assertEquals("8.8.8.8", first.addresses().getFirst().getHostAddress());
        assertThrows(SecurityException.class, () -> policy.validate(endpoint));
        assertEquals(2, resolutions.get());
    }

    @Test
    void rejectsAnyMixedPrivateAnswerAndReservedIpv6Range() throws Exception {
        WebhookDeliveryService.EndpointPolicy mixed = new WebhookDeliveryService.EndpointPolicy(
                Set.of("hooks.example.test"), host -> new InetAddress[] {
                    InetAddress.getByName("2606:4700:4700::1111"),
                    InetAddress.getByName("fd00::1")
                });
        URI endpoint = URI.create("https://hooks.example.test/payments");
        assertThrows(SecurityException.class, () -> mixed.validate(endpoint));

        List<String> reserved = List.of("::1", "fe80::1", "fc00::1", "2001:db8::1",
                "2002:7f00:1::1", "64:ff9b::7f00:1", "::ffff:127.0.0.1",
                "3fff::1");
        for (String address : reserved) {
            WebhookDeliveryService.EndpointPolicy policy =
                    new WebhookDeliveryService.EndpointPolicy(Set.of("hooks.example.test"),
                            host -> new InetAddress[] {InetAddress.getByName(address)});
            assertThrows(SecurityException.class, () -> policy.validate(endpoint), address);
        }

        WebhookDeliveryService.EndpointPolicy publicIpv6 =
                new WebhookDeliveryService.EndpointPolicy(Set.of("hooks.example.test"),
                        host -> new InetAddress[] {
                            InetAddress.getByName("2606:4700:4700::1111")});
        assertEquals(1, publicIpv6.validate(endpoint).addresses().size());
    }

    @Test
    void rejectsPrivateLinkLocalCarrierNatDocumentationAndReservedIpv4() throws Exception {
        URI endpoint = URI.create("https://hooks.example.test/payments");
        List<String> reserved = List.of("0.0.0.1", "10.0.0.1", "100.64.0.1",
                "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.0.1",
                "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1",
                "203.0.113.1", "224.0.0.1", "240.0.0.1");
        for (String address : reserved) {
            WebhookDeliveryService.EndpointPolicy policy =
                    new WebhookDeliveryService.EndpointPolicy(Set.of("hooks.example.test"),
                            host -> new InetAddress[] {InetAddress.getByName(address)});
            assertThrows(SecurityException.class, () -> policy.validate(endpoint), address);
        }
    }

    @Test
    void redirectIsTerminalAndNeverFollowed() throws Exception {
        FakeOutbox outbox = new FakeOutbox(delivery(0, 3));
        AtomicInteger calls = new AtomicInteger();
        WebhookDeliveryService service = service(outbox, request -> {
            calls.incrementAndGet();
            return new WebhookDeliveryService.HttpResult(302,
                    Map.of("location", List.of("http://127.0.0.1/admin")));
        }, InetAddress.getByName("8.8.8.8"));

        assertEquals(WebhookDeliveryService.Outcome.DEAD_LETTERED, service.deliverNext());
        assertEquals(1, calls.get());
        assertEquals("HTTP_REDIRECT_FORBIDDEN", outbox.errorCode);
    }

    @Test
    void rejectsEncodedAuthorityIpLiteralsAndUserInfoBypasses() throws Exception {
        WebhookDeliveryService.EndpointPolicy policy = new WebhookDeliveryService.EndpointPolicy(
                Set.of("hooks.example.test"), host -> new InetAddress[] {
                    InetAddress.getByName("8.8.8.8")});
        List<String> bypasses = List.of(
                "https://hooks.example.test%2e@127.0.0.1/payments",
                "https://hooks.example.test:443@127.0.0.1/payments",
                "https://hooks.example.test%252f.evil/payments",
                "https://hooks.example.test./payments",
                "https://2130706433/payments",
                "https://[::ffff:127.0.0.1]/payments");
        for (String value : bypasses) {
            URI endpoint = URI.create(value);
            assertThrows(SecurityException.class, () -> policy.validate(endpoint), value);
        }
    }

    @Test
    void keyRotationRequiresAnOverlap() {
        WebhookDeliveryService.RotatingKeyRing ring = keyRing();
        WebhookDeliveryService.SigningKey next = new WebhookDeliveryService.SigningKey("project-001", "key-new",
                "delivery-next-signing-secret-32!!".getBytes(StandardCharsets.UTF_8),
                NOW.minusSeconds(60), NOW.plusSeconds(600));
        assertThrows(IllegalArgumentException.class, () -> ring.rotate(List.of(next)));
        ring.rotate(List.of(activeKey(), next));
        ring.rotate(List.of(next));
        assertEquals("key-new", ring.current("project-001", NOW).keyId());
    }

    @Test
    void productionRuntimeLeasesProjectBoundSecretAndWipesItAfterIdleAttempt() {
        WebhookDeliveryRuntime.KeyDescriptor descriptor =
                new WebhookDeliveryRuntime.KeyDescriptor("project-001", "key-runtime",
                        "kms://webhooks/project-001", NOW.minusSeconds(30), NOW.plusSeconds(600));
        AtomicReference<WebhookDeliveryRuntime.SecretLease> leased = new AtomicReference<>();
        WebhookDeliveryRuntime runtime = new WebhookDeliveryRuntime(emptyOutboxDataSource(),
                (tenant, now) -> new WebhookDeliveryRuntime.Configuration(
                        Set.of("hooks.example.test"), List.of(descriptor)),
                (tenant, key, maximum) -> {
                    WebhookDeliveryRuntime.SecretLease value =
                            new WebhookDeliveryRuntime.SecretLease(tenant, key.projectId(),
                                    key.keyId(), key.secretReference(), "lease-runtime",
                                    NOW.plusSeconds(60), SECRET);
                    leased.set(value);
                    return value;
                }, WebhookDeliveryRuntime.Settings.productionDefaults(),
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(WebhookDeliveryService.Outcome.IDLE, runtime.runOnce("tenant-001"));
        assertThrows(IllegalStateException.class, () -> leased.get().require(descriptor,
                "tenant-001", NOW, Duration.ofMinutes(2)));
        assertTrue(leased.get().toString().contains("REDACTED"));
    }

    @Test
    void staleFencingAcknowledgementFailsClosed() {
        DataSourceWebhookOutbox outbox = new DataSourceWebhookOutbox(emptyOutboxDataSource());
        assertThrows(IllegalStateException.class,
                () -> outbox.markDelivered(delivery(0, 3), 204, NOW));
    }

    private static WebhookDeliveryService service(FakeOutbox outbox,
            WebhookDeliveryService.Transport transport, InetAddress resolved) {
        WebhookDeliveryService.EndpointPolicy policy = new WebhookDeliveryService.EndpointPolicy(
                Set.of("hooks.example.test"), host -> new InetAddress[] {resolved});
        return new WebhookDeliveryService("tenant-001", outbox, transport, policy, keyRing(),
                Duration.ofSeconds(2), Duration.ofSeconds(30), Duration.ofSeconds(5),
                Duration.ofMinutes(10), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static WebhookDeliveryService.RotatingKeyRing keyRing() {
        return new WebhookDeliveryService.RotatingKeyRing(List.of(activeKey()));
    }

    private static WebhookDeliveryService.SigningKey activeKey() {
        return new WebhookDeliveryService.SigningKey("project-001", "key-old", SECRET,
                NOW.minusSeconds(600), NOW.plusSeconds(600));
    }

    private static DataSource emptyOutboxDataSource() {
        return new DataSource() {
            @Override
            public Connection getConnection() {
                return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[] {Connection.class}, (proxy, method, arguments) ->
                                switch (method.getName()) {
                                    case "setAutoCommit", "commit", "rollback", "close" -> null;
                                    case "getAutoCommit" -> false;
                                    case "prepareStatement" -> emptyStatement();
                                    case "isClosed" -> false;
                                    case "unwrap" -> null;
                                    case "isWrapperFor" -> false;
                                    default -> defaultValue(method.getReturnType());
                                });
            }

            private PreparedStatement emptyStatement() {
                return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) ->
                                switch (method.getName()) {
                                    case "setString", "setTimestamp", "close" -> null;
                                    case "execute" -> true;
                                    case "executeQuery" -> emptyRows();
                                    default -> defaultValue(method.getReturnType());
                                });
            }

            private ResultSet emptyRows() {
                return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[] {ResultSet.class}, (proxy, method, arguments) ->
                                switch (method.getName()) {
                                    case "next" -> false;
                                    case "close" -> null;
                                    default -> defaultValue(method.getReturnType());
                                });
            }

            @Override public Connection getConnection(String username, String password) { return getConnection(); }
            @Override public <T> T unwrap(Class<T> iface) { return null; }
            @Override public boolean isWrapperFor(Class<?> iface) { return false; }
            @Override public java.io.PrintWriter getLogWriter() { return null; }
            @Override public void setLogWriter(java.io.PrintWriter out) {}
            @Override public void setLoginTimeout(int seconds) {}
            @Override public int getLoginTimeout() { return 0; }
            @Override public java.util.logging.Logger getParentLogger() {
                return java.util.logging.Logger.getGlobal();
            }
        };
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }

    private static boolean allZero(byte[] value) {
        for (byte item : value) {
            if (item != 0) {
                return false;
            }
        }
        return true;
    }

    private static WebhookDeliveryService.Delivery delivery(int attempt, int maximum) {
        return new WebhookDeliveryService.Delivery(1, "tenant-001", "project-001", "endpoint-001",
                URI.create("https://hooks.example.test/payments"), "evt-001", "payment.succeeded",
                "{\"event\":true}".getBytes(StandardCharsets.UTF_8), attempt, maximum,
                "worker-lease-001", 7);
    }

    private static final class FakeOutbox implements WebhookDeliveryService.Outbox {
        private WebhookDeliveryService.Delivery pending;
        private String state = "PENDING";
        private String errorCode = "";
        private Instant nextAttemptAt = Instant.EPOCH;

        private FakeOutbox(WebhookDeliveryService.Delivery pending) {
            this.pending = pending;
        }

        @Override
        public Optional<WebhookDeliveryService.Delivery> claim(String tenantId, Instant now,
                Instant leaseUntil) {
            WebhookDeliveryService.Delivery result = pending;
            pending = null;
            state = result == null ? state : "IN_FLIGHT";
            return Optional.ofNullable(result);
        }

        @Override
        public void markDelivered(WebhookDeliveryService.Delivery delivery, int statusCode,
                Instant deliveredAt) {
            state = "DELIVERED";
        }

        @Override
        public void reschedule(WebhookDeliveryService.Delivery delivery, int statusCode,
                String failure,
                Instant next) {
            state = "RETRY";
            errorCode = failure;
            nextAttemptAt = next;
        }

        @Override
        public void deadLetter(WebhookDeliveryService.Delivery delivery, int statusCode,
                String failure,
                Instant failedAt) {
            state = "DEAD";
            errorCode = failure;
        }
    }
}
