package com.elmpay.payment.commerce;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcCommerceServiceTest {
    private final DataSource unreachable = (DataSource) java.lang.reflect.Proxy.newProxyInstance(
            getClass().getClassLoader(), new Class<?>[] {DataSource.class},
            (proxy, method, arguments) -> {
                throw new AssertionError("validation failure must not reach the database");
            });

    @Test
    void opaquePaymentReferencesRejectPanAndAcceptOfficialTokens() {
        assertTrue(JdbcCommerceService.paymentReference("psp://stripe/pm_123").startsWith("psp://"));
        assertThrows(CommerceRuntimeException.class,
                () -> JdbcCommerceService.paymentReference("4111 1111 1111 1111"));
        assertThrows(CommerceRuntimeException.class,
                () -> JdbcCommerceService.paymentReference("token-with-cvv-123"));
    }

    @Test
    void unverifiedProviderResultsFailBeforePersistence() {
        JdbcCommerceService service = new JdbcCommerceService(unreachable, Clock.systemUTC());
        CommerceService.Context context = new CommerceService.Context(UUID.randomUUID(),
                UUID.randomUUID(), "worker");
        CommerceService.DisputeEvent event = new CommerceService.DisputeEvent("stripe", "evt",
                "dp", UUID.randomUUID(), 100, "USD", Instant.now().plusSeconds(600),
                "a".repeat(64), null);
        assertThrows(CommerceRuntimeException.class,
                () -> service.ingestDispute(context, event, UUID.randomUUID().toString()));
        assertThrows(CommerceRuntimeException.class, () -> service.recordRenewalOutcome(context,
                UUID.randomUUID(), CommerceService.RenewalOutcome.SUCCEEDED, "b".repeat(64),
                null, "key", UUID.randomUUID().toString()));
    }

    @Test
    void commerceMigrationHasDurableIsolationAndOutboxBindings() throws Exception {
        try (var input = getClass().getResourceAsStream(
                "/db/migration/V066__durable_commerce_runtime.sql")) {
            assertNotNull(input);
            String sql = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            for (String table : new String[] {"provider_dispute", "dispute_event_inbox",
                    "dispute_evidence", "billing_plan", "billing_mandate",
                    "billing_subscription", "subscription_usage_inbox",
                    "subscription_billing_cycle", "dunning_case", "billing_adjustment",
                    "commerce_action_receipt"}) {
                assertTrue(sql.contains(table), table);
            }
            assertTrue(sql.contains("FORCE ROW LEVEL SECURITY"));
            assertTrue(sql.contains("current_setting(''app.tenant_id'', true)"));
            assertTrue(sql.contains("commerce history is immutable"));
            assertTrue(sql.contains("payment_method_reference ~ '^(psp|wallet|mandate)://"));
        }
        try (var input = getClass().getResourceAsStream(
                "/db/migration/V066_1__provider_evidence_receipts.sql")) {
            assertNotNull(input);
            String sql = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(sql.contains("CREATE TABLE IF NOT EXISTS provider_evidence_nonce"));
            assertTrue(sql.contains("verification_receipt_digest"));
            assertTrue(sql.contains("new dispute events require verified provider evidence"));
            assertTrue(sql.contains("FORCE ROW LEVEL SECURITY"));
        }
    }
}
