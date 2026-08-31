package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class ProviderWebhookVerifiersTest {
    private static final UUID TENANT = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID ACCOUNT = UUID.fromString("10000000-0000-4000-8000-000000000002");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void productionProviderVerificationFlowsIntoJdbcInboxAfterScopeBinding() {
        AtomicReference<WebhookRequest> verifiedRequest = new AtomicReference<>();
        ProviderAdapter provider = new StubAdapter("stripe", request -> {
            verifiedRequest.set(request);
            if (!"valid".equals(request.headers().get("stripe-signature"))) {
                throw new SecurityException("signature rejected");
            }
            return verifiedEvent(TENANT, ACCOUNT);
        });
        AtomicReference<Map<Integer, Object>> inserted = new AtomicReference<>();
        AtomicBoolean committed = new AtomicBoolean();
        WebhookIngressService service = new WebhookIngressService(
                ProviderWebhookVerifiers.create(List.of(provider)),
                new DataSourceWebhookInbox(recordingDataSource(inserted, committed)));
        byte[] body = "{\"safe\":true}".getBytes(StandardCharsets.UTF_8);

        WebhookIngressService.Receipt receipt = service.ingest(context(),
                Map.of("stripe-signature", "valid"), body);

        assertEquals(WebhookIngressService.Outcome.ACCEPTED, receipt.outcome());
        assertEquals(TENANT, verifiedRequest.get().tenantId());
        assertEquals(ACCOUNT, verifiedRequest.get().merchantAccountId());
        assertArrayEquals(new byte[body.length], verifiedRequest.get().rawBody());
        assertArrayEquals("{\"safe\":true}".getBytes(StandardCharsets.UTF_8), body);
        assertTrue(committed.get());
        assertEquals(TENANT.toString(), inserted.get().get(1));
        assertEquals("stripe", inserted.get().get(3));
        assertEquals("evt-production", inserted.get().get(5));
        assertEquals(1250L, inserted.get().get(12));
        assertEquals("USD", inserted.get().get(13));
        assertEquals(WebhookIngressService.CANONICAL_SCHEMA_V1, inserted.get().get(14));
        assertEquals(receipt.rawBodySha256(), inserted.get().get(15));
        String canonical = new String((byte[]) inserted.get().get(16), StandardCharsets.UTF_8);
        assertTrue(canonical.contains("\"business_order_no\":\"order-production\""));
        assertTrue(canonical.contains("\"tenant_id\":\"" + TENANT + "\""));
        assertTrue(canonical.contains("\"schema\":\"provider-webhook-effect.v1\""));
        assertFalse(canonical.contains("provider_object_id"));
        assertEquals(WebhookVerificationDigests.sha256((byte[]) inserted.get().get(16)),
                inserted.get().get(17));
        assertTrue(inserted.get().get(18).toString().matches("[0-9a-f]{64}"));
        assertFalse(inserted.get().values().stream().anyMatch(value -> value instanceof byte[] bytes
                && java.util.Arrays.equals(body, bytes)));
    }

    @Test
    void providerCannotSubstituteVerifiedTenantScope() {
        ProviderAdapter provider = new StubAdapter("stripe", request -> verifiedEvent(
                UUID.fromString("20000000-0000-4000-8000-000000000001"), ACCOUNT));
        WebhookIngressService service = new WebhookIngressService(
                ProviderWebhookVerifiers.create(List.of(provider)),
                (context, event, digest) -> true);
        assertThrows(SecurityException.class, () -> service.ingest(context(), Map.of(),
                "{}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void duplicateOrNonCallbackProviderRegistrationFailsClosed() {
        ProviderAdapter stripe = new StubAdapter("stripe", request -> verifiedEvent(TENANT, ACCOUNT));
        assertThrows(IllegalArgumentException.class,
                () -> ProviderWebhookVerifiers.create(List.of(stripe, stripe)));
        ProviderAdapter apple = new StubAdapter("apple_pay",
                request -> verifiedEvent(TENANT, ACCOUNT));
        assertThrows(IllegalArgumentException.class,
                () -> ProviderWebhookVerifiers.create(List.of(apple)));
    }

    @Test
    void canonicalSchemaDropsUnknownProviderFactsButRawDigestStillBindsRequest() {
        ProviderAdapter provider = new StubAdapter("stripe", request -> new VerifiedProviderEvent(
                TENANT, ACCOUNT, "evt-production", "payment.succeeded", "pi-production",
                "order-production", Money.of(1250, "USD"), "key-production",
                NOW.minusSeconds(1), Map.of("provider_object_id", "pi-production",
                        "untrusted_free_form", "must-not-persist", "out_of_order", "false")));
        AtomicReference<WebhookIngressService.VerifiedEvent> stored = new AtomicReference<>();
        AtomicReference<String> rawDigest = new AtomicReference<>();
        WebhookIngressService service = new WebhookIngressService(
                ProviderWebhookVerifiers.create(List.of(provider)), (context, event, digest) -> {
                    stored.set(event);
                    rawDigest.set(digest);
                    return true;
                });
        byte[] raw = "{\"provider_payload\":\"fully-bound-by-digest\"}"
                .getBytes(StandardCharsets.UTF_8);

        service.ingest(context(), Map.of(), raw);

        String canonical = new String(stored.get().canonicalPayload(), StandardCharsets.UTF_8);
        assertFalse(canonical.contains("untrusted_free_form"));
        assertFalse(canonical.contains("provider_object_id"));
        assertTrue(canonical.contains("\"provider_out_of_order\":\"false\""));
        assertEquals(WebhookVerificationDigests.sha256(raw), rawDigest.get());
    }

    @Test
    void sensitiveOrMalformedProviderFactsFailBeforeInbox() {
        AtomicBoolean stored = new AtomicBoolean();
        ProviderAdapter sensitive = new StubAdapter("stripe", request -> new VerifiedProviderEvent(
                TENANT, ACCOUNT, "evt-production", "payment.succeeded", "pi-production",
                "order-production", Money.of(1250, "USD"), "key-production", NOW,
                Map.of("customer_card_number", "4242424242424242")));
        WebhookIngressService service = new WebhookIngressService(
                ProviderWebhookVerifiers.create(List.of(sensitive)), (context, event, digest) -> {
                    stored.set(true);
                    return true;
                });

        assertThrows(SecurityException.class, () -> service.ingest(context(), Map.of(),
                "{}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(stored.get());
    }

    private static WebhookIngressService.Context context() {
        return new WebhookIngressService.Context(TENANT.toString(), UUID.randomUUID().toString(),
                "stripe", ACCOUNT.toString(), NOW);
    }

    private static VerifiedProviderEvent verifiedEvent(UUID tenant, UUID account) {
        return new VerifiedProviderEvent(tenant, account, "evt-production", "payment.succeeded",
                "pi-production", "order-production", Money.of(1250, "USD"), "key-production",
                NOW.minusSeconds(1), Map.of("provider_object_id", "pi-production"));
    }

    private static DataSource recordingDataSource(
            AtomicReference<Map<Integer, Object>> inserted, AtomicBoolean committed) {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(),
                new Class<?>[] {DataSource.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("getConnection")) {
                        return connection(inserted, committed);
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Connection connection(AtomicReference<Map<Integer, Object>> inserted,
            AtomicBoolean committed) {
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, arguments) -> {
                    return switch (method.getName()) {
                        case "prepareStatement" -> statement((String) arguments[0], inserted);
                        case "commit" -> {
                            committed.set(true);
                            yield null;
                        }
                        default -> defaultValue(method.getReturnType());
                    };
                });
    }

    private static PreparedStatement statement(String sql,
            AtomicReference<Map<Integer, Object>> inserted) {
        Map<Integer, Object> values = new HashMap<>();
        boolean insert = sql.startsWith("INSERT INTO provider_webhook_inbox");
        return (PreparedStatement) Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> {
                    if (method.getName().startsWith("set") && insert) {
                        Object value = arguments[1];
                        values.put((Integer) arguments[0], value instanceof byte[] bytes
                                ? bytes.clone() : value);
                        return null;
                    }
                    if (method.getName().equals("executeUpdate")) {
                        inserted.set(Map.copyOf(values));
                        return 1;
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0F;
        }
        if (type == double.class) {
            return 0D;
        }
        if (type == char.class) {
            return '\0';
        }
        return null;
    }

    private record StubAdapter(String provider,
            Function<WebhookRequest, VerifiedProviderEvent> webhook) implements ProviderAdapter {
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) { throw unused(); }
        @Override public ProviderPayment queryPayment(ProviderRequestContext context, String id,
                String order) { throw unused(); }
        @Override public ProviderPayment capture(ProviderRequestContext context, String id,
                Money amount) { throw unused(); }
        @Override public ProviderPayment cancel(ProviderRequestContext context, String id,
                String reason) { throw unused(); }
        @Override public ProviderRefund refund(RefundCommand command) { throw unused(); }
        @Override public ProviderRefund queryRefund(ProviderRequestContext context, String id,
                String reference) { throw unused(); }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            return webhook.apply(request);
        }
        private static UnsupportedOperationException unused() {
            return new UnsupportedOperationException("unused provider operation");
        }
    }
}
