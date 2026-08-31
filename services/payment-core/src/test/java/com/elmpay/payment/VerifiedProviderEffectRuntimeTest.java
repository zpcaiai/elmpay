package com.elmpay.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.VerifiedProviderEffectCommand.EffectKind;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class VerifiedProviderEffectRuntimeTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void commandRejectsMoneyMismatchShapeAndFutureProviderTime() {
        assertThrows(IllegalArgumentException.class, () -> command(
                EffectKind.PAYMENT_CAPTURED, 100L, null, NOW));
        assertThrows(IllegalArgumentException.class, () -> command(
                EffectKind.REFUND_SUCCEEDED, null, null, NOW));
        assertThrows(IllegalArgumentException.class, () -> command(
                EffectKind.PAYMENT_CAPTURED, 100L, "USD", NOW.plusSeconds(301)));
    }

    @Test
    void businessOrderDigestIsDeterministicAndBoundarySensitive() {
        String first = ProviderEffectExpectationService.businessOrderDigest("order-001");
        assertEquals(first,
                ProviderEffectExpectationService.businessOrderDigest("order-001"));
        assertNotEquals(first,
                ProviderEffectExpectationService.businessOrderDigest("order-002"));
        assertTrue(first.matches("[0-9a-f]{64}"));
    }

    @Test
    void expectationRequiresCallerOwnedTransactionBeforeAnyWrite() {
        Connection autoCommit = (Connection) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {Connection.class},
                (proxy, method, arguments) -> method.getName().equals("getAutoCommit")
                        ? true : null);
        ProviderEffectExpectationService service = new ProviderEffectExpectationService();
        assertThrows(IllegalStateException.class, () -> service.registerCapture(autoCommit,
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), "stripe", 100, "USD",
                ProviderEffectExpectationService.businessOrderDigest("order-001"), NOW));
    }

    @Test
    void migrationEnforcesImmutableExpectationsApplicationsAndTenantRls() throws IOException {
        String sql = resource("db/migration/V036_2__verified_provider_effect_runtime.sql");
        assertTrue(sql.contains("CREATE TABLE provider_effect_expectation"));
        assertTrue(sql.contains("PRIMARY KEY (tenant_id, payment_attempt_id)"));
        assertTrue(sql.contains("expected_delta_minor bigint NOT NULL CHECK"));
        assertTrue(sql.contains("CREATE TABLE provider_effect_application"));
        assertTrue(sql.contains("verification_digest char(64) NOT NULL"));
        assertTrue(sql.contains("CREATE TABLE provider_effect_target_clock"));
        assertEquals(3, occurrences(sql, "ENABLE ROW LEVEL SECURITY"));
        assertEquals(3, occurrences(sql, "FORCE ROW LEVEL SECURITY"));
        assertEquals(2, occurrences(sql, "BEFORE UPDATE OR DELETE"));
        assertTrue(sql.contains("current_setting('app.tenant_id', true)"));
    }

    private static VerifiedProviderEffectCommand command(EffectKind kind, Long amount,
            String currency, Instant occurredAt) {
        return new VerifiedProviderEffectCommand(VerifiedProviderEffectCommand.SCHEMA_V1,
                VerifiedProviderEffectCommand.MAPPING_V1, UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), "stripe", "evt-001", "payment_intent.succeeded", kind,
                "pi_001", "order-001", amount, currency, occurredAt, NOW,
                "a".repeat(64), "b".repeat(64), "webhook-aaaaaaaaaaaaaaaa");
    }

    private static int occurrences(String source, String needle) {
        return (source.length() - source.replace(needle, "").length()) / needle.length();
    }

    private static String resource(String name) throws IOException {
        try (var input = VerifiedProviderEffectRuntimeTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("missing test resource " + name);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
