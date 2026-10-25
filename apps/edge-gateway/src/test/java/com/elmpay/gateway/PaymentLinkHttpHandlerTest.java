package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.checkout.DurablePaymentLinkService;
import com.elmpay.payment.checkout.HmacPaymentLinkSigner;
import com.elmpay.payment.checkout.InMemoryPaymentLinkRepository;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

/** Actual local-mode product objects and HTTP; no service/authentication doubles. */
final class PaymentLinkHttpHandlerTest {
    @Test
    void createReplayAndAnonymousOneTimeRedemptionPreserveTheAuthenticatedScope() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            UUID session = UUID.randomUUID();
            String body = creation(session, 60L);
            HttpResponse<String> first = fixture.post("/v1/payment-links", body,
                    Map.of("Idempotency-Key", "create-once"), Set.of());
            assertEquals(201, first.statusCode());
            assertEquals("no-store", first.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals("application/json; charset=utf-8",
                    first.headers().firstValue("Content-Type").orElseThrow());
            Map<String, Object> link = Json.object(first.body());
            String token = (String) link.get("token");
            assertEquals(session.toString(), link.get("checkout_session_id"));
            assertEquals(fixture.clock.instant().plusSeconds(60).toString(), link.get("expires_at"));
            assertTrue(("/checkout/link/" + token).equals(link.get("qr_payload")));
            HttpResponse<String> replay = fixture.post("/v1/payment-links", body,
                    Map.of("Idempotency-Key", "create-once"), Set.of());
            assertEquals(201, replay.statusCode());
            assertTrue(token.equals(Json.object(replay.body()).get("token")));

            String redemption = Json.stringify(Map.of("token", token));
            Set<String> anonymous = Set.of("Authorization", "X-Project-Id", "Idempotency-Key");
            HttpResponse<String> used = fixture.post("/api/payment-links/redeem", redemption,
                    Map.of(), anonymous);
            assertEquals(200, used.statusCode());
            Map<String, Object> facts = Json.object(used.body());
            assertEquals(fixture.tenant.toString(), facts.get("tenant_id"));
            assertEquals(fixture.project.toString(), facts.get("project_id"));
            assertEquals(session.toString(), facts.get("checkout_session_id"));
            assertEquals(fixture.clock.instant().toString(), facts.get("consumed_at"));
            HttpResponse<String> duplicate = fixture.post("/api/payment-links/redeem", redemption,
                    Map.of(), anonymous);
            assertEquals(401, duplicate.statusCode());
            assertEquals("invalid_payment_link", errorCode(duplicate));
            assertFalse(duplicate.body().contains(token));
        }
    }

    @Test
    void authenticationScopeAndProjectCannotBeSelectedByTheCaller() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE);
                Fixture reader = new Fixture(ApiPrincipal.PAYMENTS_READ)) {
            String body = creation(UUID.randomUUID(), 60L);
            assertEquals(401, fixture.post("/v1/payment-links", body, Map.of(),
                    Set.of("Authorization")).statusCode());
            assertEquals(401, fixture.post("/v1/payment-links", body,
                    Map.of("Authorization", "Bearer " + UUID.randomUUID()), Set.of()).statusCode());
            HttpResponse<String> forbidden = reader.post("/v1/payment-links", body,
                    Map.of(), Set.of());
            assertEquals(403, forbidden.statusCode());
            assertEquals("forbidden", errorCode(forbidden));
            assertEquals(403, fixture.post("/v1/payment-links", body,
                    Map.of("X-Project-Id", UUID.randomUUID().toString()), Set.of()).statusCode());
            assertEquals(400, fixture.post("/v1/payment-links", body, Map.of(),
                    Set.of("X-Project-Id")).statusCode());
            assertEquals(400, fixture.post("/v1/payment-links?tenant_id=" + UUID.randomUUID(), body,
                    Map.of(), Set.of()).statusCode());
        }
    }

    @Test
    void malformedMetadataCannotReachLinkCreation() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            String body = creation(UUID.randomUUID(), 60L);
            for (Set<String> absent : List.of(Set.of("X-Request-Id"), Set.of("traceparent"))) {
                HttpResponse<String> denied = fixture.post("/v1/payment-links", body,
                        Map.of(), absent);
                assertEquals(400, denied.statusCode());
                UUID.fromString(denied.headers().firstValue("X-Request-Id").orElseThrow());
                assertEquals("invalid_request", errorCode(denied));
            }
            for (Map<String, String> invalid : List.of(
                    Map.of("X-Request-Id", "not-a-request-id"),
                    Map.of("traceparent", "not-a-trace"),
                    Map.of("traceparent", "00-00000000000000000000000000000000-0123456789abcdef-01"),
                    Map.of("traceparent", "00-0123456789abcdef0123456789abcdef-0000000000000000-01"))) {
                assertEquals(400, fixture.post("/v1/payment-links", body, invalid, Set.of()).statusCode());
            }
        }
    }

    @Test
    void boundedJsonAndIdempotencyRemainRequired() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            String valid = creation(UUID.randomUUID(), 60L);
            assertEquals(400, fixture.post("/v1/payment-links", valid, Map.of(),
                    Set.of("Idempotency-Key")).statusCode());
            assertEquals(400, fixture.post("/v1/payment-links", valid,
                    Map.of("Content-Type", "text/plain"), Set.of()).statusCode());
            assertEquals(400, fixture.post("/v1/payment-links", valid, Map.of(),
                    Set.of("Content-Type")).statusCode());
            for (String invalid : List.of("[]", "{}", "x".repeat(8_193),
                    "{\"checkout_session_id\":\"invalid\",\"ttl_seconds\":60}",
                    "{\"checkout_session_id\":null,\"ttl_seconds\":60}",
                    "{\"checkout_session_id\":\"" + UUID.randomUUID() + "\",\"ttl_seconds\":\"60\"}",
                    "{\"checkout_session_id\":\"" + UUID.randomUUID() + "\",\"ttl_seconds\":1.5}",
                    creation(UUID.randomUUID(), 0L), creation(UUID.randomUUID(), -1L),
                    creation(UUID.randomUUID(), 901L),
                    valid.substring(0, valid.length() - 1) + ",\"tenant_id\":\"foreign\"}")) {
                HttpResponse<String> denied = fixture.post("/v1/payment-links", invalid,
                        Map.of(), Set.of());
                assertEquals(400, denied.statusCode());
                assertEquals("invalid_request", errorCode(denied));
            }
        }
    }

    @Test
    void tamperedExpiredAndConflictingRequestsCannotBecomeSuccessful() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            UUID session = UUID.randomUUID();
            String token = fixture.links.create(fixture.tenant, fixture.project, session,
                    Duration.ofMinutes(1), "conflicting-create").token();
            HttpResponse<String> conflict = fixture.post("/v1/payment-links",
                    creation(UUID.randomUUID(), 60L),
                    Map.of("Idempotency-Key", "conflicting-create"), Set.of());
            assertEquals(503, conflict.statusCode());
            assertEquals("payment_link_unavailable", errorCode(conflict));
            String tampered = token.substring(0, token.length() - 1)
                    + (token.endsWith("A") ? "B" : "A");
            DurablePaymentLinkService past = new DurablePaymentLinkService(fixture.repository,
                    fixture.signer, Clock.offset(fixture.clock, Duration.ofSeconds(-2)));
            String expired = past.create(fixture.tenant, fixture.project, UUID.randomUUID(),
                    Duration.ofSeconds(1), "expired").token();
            for (String invalid : List.of("invalid-test-link-" + UUID.randomUUID(), tampered, expired)) {
                HttpResponse<String> denied = fixture.post("/api/payment-links/redeem",
                        Json.stringify(Map.of("token", invalid)), Map.of(), Set.of("Authorization"));
                assertEquals(401, denied.statusCode());
                assertEquals("invalid_payment_link", errorCode(denied));
                assertFalse(denied.body().contains(invalid));
            }
            assertEquals(200, fixture.post("/api/payment-links/redeem",
                    Json.stringify(Map.of("token", token)), Map.of(), Set.of("Authorization")).statusCode());
        }
    }

    @Test
    void authenticatedCreateRateLimitHasARealSixtyRequestBoundary() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            String body = creation(UUID.randomUUID(), 60L);
            String firstToken = null;
            for (int attempt = 0; attempt < 60; attempt++) {
                HttpResponse<String> response = fixture.post("/v1/payment-links", body,
                        Map.of("Idempotency-Key", "rate-create"), Set.of());
                assertEquals(201, response.statusCode());
                String token = (String) Json.object(response.body()).get("token");
                if (firstToken == null) firstToken = token;
                assertTrue(firstToken.equals(token));
            }
            HttpResponse<String> denied = fixture.post("/v1/payment-links", body,
                    Map.of("Idempotency-Key", "rate-create"), Set.of());
            assertEquals(429, denied.statusCode());
            assertEquals("rate_limited", errorCode(denied));
        }
    }

    @Test
    void anonymousInvalidRedemptionsAreAlsoRateLimited() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            String body = Json.stringify(Map.of("token", "invalid"));
            for (int attempt = 0; attempt < 60; attempt++) {
                assertEquals(401, fixture.post("/api/payment-links/redeem", body,
                        Map.of(), Set.of("Authorization")).statusCode());
            }
            HttpResponse<String> denied = fixture.post("/api/payment-links/redeem", body,
                    Map.of(), Set.of("Authorization"));
            assertEquals(429, denied.statusCode());
            assertEquals("rate_limited", errorCode(denied));
        }
    }

    @Test
    void unsupportedRoutesAndMissingRuntimeObjectsFailClosed() throws Exception {
        try (Fixture fixture = new Fixture(ApiPrincipal.PAYMENTS_WRITE)) {
            assertEquals(404, fixture.send("GET", "/v1/payment-links", "{}", Map.of(), Set.of()).statusCode());
            assertEquals(404, fixture.post("/v1/payment-links/unknown", "{}", Map.of(), Set.of()).statusCode());
            assertThrows(NullPointerException.class, () -> new PaymentLinkHttpHandler(null, fixture.links));
            assertThrows(NullPointerException.class,
                    () -> new PaymentLinkHttpHandler(fixture.authenticator, null));
            assertThrows(NullPointerException.class,
                    () -> new PaymentLinkHttpHandler(fixture.authenticator, fixture.links, null));
        }
    }

    private static String creation(UUID session, Object ttl) {
        return Json.stringify(Map.of("checkout_session_id", session, "ttl_seconds", ttl));
    }

    private static String errorCode(HttpResponse<String> response) {
        Object error = Json.object(response.body()).get("error");
        assertTrue(error instanceof Map<?, ?>);
        return (String) ((Map<?, ?>) error).get("code");
    }

    private static final class Fixture implements AutoCloseable {
        private final UUID tenant = UUID.randomUUID();
        private final UUID project = UUID.randomUUID();
        private final String credential = UUID.randomUUID().toString() + UUID.randomUUID();
        private final Clock clock = Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC);
        private final InMemoryPaymentLinkRepository repository = new InMemoryPaymentLinkRepository();
        private final HmacPaymentLinkSigner signer;
        private final DurablePaymentLinkService links;
        private final ApiKeyAuthenticator authenticator;
        private final HttpServer server;
        private final HttpClient client = HttpClient.newHttpClient();
        private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

        private Fixture(String scope) throws IOException {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            signer = new HmacPaymentLinkSigner(Map.of("ci-local-v1", key), "ci-local-v1");
            java.util.Arrays.fill(key, (byte) 0);
            links = new DurablePaymentLinkService(repository, signer, clock);
            authenticator = ApiKeyAuthenticator.parse(ApiKeyAuthenticator.digestForProvisioning(credential)
                    + "|native-link-test|" + tenant + "|" + project + "|" + UUID.randomUUID() + "|" + scope);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", new PaymentLinkHttpHandler(authenticator, links, clock));
            server.setExecutor(executor);
            server.start();
        }

        private HttpResponse<String> post(String path, String body, Map<String, String> overrides,
                Set<String> omitted) throws IOException, InterruptedException {
            return send("POST", path, body, overrides, omitted);
        }

        private HttpResponse<String> send(String method, String path, String body,
                Map<String, String> overrides, Set<String> omitted) throws IOException, InterruptedException {
            Map<String, String> headers = new LinkedHashMap<>(Map.of(
                    "Authorization", "Bearer " + credential, "X-Project-Id", project.toString(),
                    "X-Request-Id", UUID.randomUUID().toString(), "Idempotency-Key", UUID.randomUUID().toString(),
                    "traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
                    "Content-Type", "application/json"));
            headers.putAll(overrides);
            omitted.forEach(headers::remove);
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:"
                    + server.getAddress().getPort() + path)).timeout(Duration.ofSeconds(10));
            headers.forEach(request::header);
            request.method(method, "GET".equals(method) ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(body));
            return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        }

        @Override
        public void close() {
            server.stop(0);
            client.close();
            executor.close();
        }
    }
}
