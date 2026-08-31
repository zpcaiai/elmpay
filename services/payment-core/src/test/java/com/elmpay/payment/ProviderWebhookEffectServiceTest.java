package com.elmpay.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.ProviderWebhookEffectService.EffectRejectedException;
import com.elmpay.payment.ProviderWebhookEffectService.Outcome;
import com.elmpay.payment.VerifiedProviderEffectCommand.EffectKind;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class ProviderWebhookEffectServiceTest {
    private static final UUID TENANT =
            UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT =
            UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID ACCOUNT =
            UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final UUID INTENT =
            UUID.fromString("00000000-0000-4000-8000-000000000004");
    private static final UUID ATTEMPT =
            UUID.fromString("00000000-0000-4000-8000-000000000005");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void stateOutboxApplicationAndInboxCallerUseOneUncommittedConnection() {
        FakeJdbc jdbc = FakeJdbc.payment();
        ProviderWebhookEffectService.Result result = service().apply(jdbc.connection(),
                command(EffectKind.PAYMENT_CAPTURED, "order-001", 100L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64)));

        assertEquals(Outcome.APPLIED, result.outcome());
        assertEquals(INTENT, result.targetId());
        assertTrue(jdbc.writes.stream().anyMatch(sql -> sql.startsWith("UPDATE payment_intent")));
        assertTrue(jdbc.writes.stream().anyMatch(sql -> sql.startsWith("UPDATE payment_attempt")));
        assertTrue(jdbc.writes.stream().anyMatch(sql -> sql.startsWith("INSERT INTO outbox_event")));
        assertTrue(jdbc.writes.stream().anyMatch(
                sql -> sql.startsWith("INSERT INTO provider_effect_application")));
        assertEquals(List.of("payment.captured.v1", "payment_intent.captured"),
                jdbc.outboxEventNames);
        assertTrue(jdbc.outboxPayloads.getLast().contains("\"amount_minor\":100"));
        assertTrue(jdbc.outboxPayloads.getLast().contains("\"captured_at\""));
        assertFalse(jdbc.commitCalled);
        assertFalse(jdbc.rollbackCalled);
        assertTrue(result.semanticRevision() > 0);
    }

    @Test
    void forgedBusinessBindingAndMoneyMismatchFailBeforeAnyBusinessWrite() {
        FakeJdbc forged = FakeJdbc.payment();
        EffectRejectedException binding = assertThrows(EffectRejectedException.class,
                () -> service().apply(forged.connection(), command(
                        EffectKind.PAYMENT_CAPTURED, "other-tenant-order", 100L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64))));
        assertTrue(binding.permanent());
        assertEquals("PROVIDER_EFFECT_PAYMENT_BINDING_CONFLICT", binding.failureCode());
        assertTrue(forged.writes.isEmpty());

        FakeJdbc amount = FakeJdbc.payment();
        EffectRejectedException money = assertThrows(EffectRejectedException.class,
                () -> service().apply(amount.connection(), command(
                        EffectKind.PAYMENT_CAPTURED, "order-001", 99L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64))));
        assertTrue(money.permanent());
        assertTrue(amount.writes.isEmpty());
    }

    @Test
    void duplicateIsIdempotentButEventIdHashConflictIsPermanentlyRejected() {
        FakeJdbc duplicate = FakeJdbc.payment();
        duplicate.existingApplication = application("a".repeat(64), "b".repeat(64));
        ProviderWebhookEffectService.Result replay = service().apply(duplicate.connection(),
                command(EffectKind.PAYMENT_CAPTURED, "order-001", 100L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64)));
        assertEquals(Outcome.DUPLICATE, replay.outcome());
        assertTrue(duplicate.writes.isEmpty());
        assertNull(replay.semanticEventId());

        FakeJdbc conflict = FakeJdbc.payment();
        conflict.existingApplication = application("c".repeat(64), "b".repeat(64));
        EffectRejectedException rejection = assertThrows(EffectRejectedException.class,
                () -> service().apply(conflict.connection(), command(
                        EffectKind.PAYMENT_CAPTURED, "order-001", 100L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64))));
        assertEquals("PROVIDER_EFFECT_IDENTITY_CONFLICT", rejection.failureCode());
        assertTrue(rejection.permanent());
        assertTrue(conflict.writes.isEmpty());
    }

    @Test
    void terminalPaymentCannotDowngradeAndOlderNonterminalEventIsNoop() {
        FakeJdbc terminal = FakeJdbc.payment();
        terminal.paymentRows = List.of(paymentRow("captured", "succeeded", "payment", 100));
        EffectRejectedException downgrade = assertThrows(EffectRejectedException.class,
                () -> service().apply(terminal.connection(), command(
                        EffectKind.PAYMENT_FAILED, "order-001", 100L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64))));
        assertEquals("PROVIDER_EFFECT_TERMINAL_CONFLICT", downgrade.failureCode());
        assertTrue(terminal.writes.isEmpty());

        FakeJdbc outOfOrder = FakeJdbc.payment();
        outOfOrder.targetClock = Map.of(
                "last_provider_occurred_at", Timestamp.from(NOW),
                "last_provider_event_id", "evt-newer",
                "last_effect_kind", "PAYMENT_PENDING");
        ProviderWebhookEffectService.Result result = service().apply(outOfOrder.connection(),
                command(EffectKind.PAYMENT_AUTHORIZED, "order-001", 100L, "USD",
                        NOW.minusSeconds(30), "a".repeat(64)));
        assertEquals(Outcome.NOOP_OUT_OF_ORDER, result.outcome());
        assertFalse(outOfOrder.writes.stream().anyMatch(sql -> sql.startsWith("UPDATE payment")));
        assertFalse(outOfOrder.writes.stream().anyMatch(sql -> sql.startsWith("INSERT INTO outbox")));
        assertTrue(outOfOrder.writes.stream().anyMatch(
                sql -> sql.startsWith("INSERT INTO provider_effect_application")));
    }

    @Test
    void crossTenantTransactionIsRejectedBeforeBindingOrMutation() {
        FakeJdbc jdbc = FakeJdbc.payment();
        jdbc.tenantScope = "00000000-0000-4000-8000-000000000099";
        EffectRejectedException rejection = assertThrows(EffectRejectedException.class,
                () -> service().apply(jdbc.connection(), command(
                        EffectKind.PAYMENT_CAPTURED, "order-001", 100L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64))));
        assertEquals("PROVIDER_EFFECT_TENANT_SCOPE_MISMATCH", rejection.failureCode());
        assertTrue(jdbc.writes.isEmpty());
    }

    @Test
    void partialCaptureRequiresOneExactPersistedExpectation() {
        FakeJdbc exact = FakeJdbc.payment();
        exact.paymentRows = List.of(paymentRow("authorized", "pending", "capture", 40));
        ProviderWebhookEffectService.Result result = service().apply(exact.connection(),
                command(EffectKind.PAYMENT_CAPTURED, "order-001", 40L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64)));
        assertEquals(Outcome.APPLIED, result.outcome());
        assertEquals(List.of("payment.partially_captured.v1", "payment_intent.captured"),
                exact.outboxEventNames);
        assertTrue(exact.outboxPayloads.getLast().contains("\"amount_minor\":40"),
                "semantic capture must carry the exact delta, never cumulative captured money");

        FakeJdbc ambiguous = FakeJdbc.payment();
        ambiguous.paymentRows = List.of(
                paymentRow("authorized", "pending", "capture", 40),
                paymentRow("authorized", "pending", "capture", 40));
        EffectRejectedException rejection = assertThrows(EffectRejectedException.class,
                () -> service().apply(ambiguous.connection(), command(
                        EffectKind.PAYMENT_CAPTURED, "order-001", 40L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64))));
        assertEquals("PROVIDER_EFFECT_CAPTURE_BINDING_AMBIGUOUS", rejection.failureCode());
    }

    @Test
    void successfulRefundKeepsLegacyStateEventAndEmitsOneLedgerDrivingExactDelta() {
        FakeJdbc jdbc = FakeJdbc.refund();
        ProviderWebhookEffectService.Result result = service().apply(jdbc.connection(),
                command(EffectKind.REFUND_SUCCEEDED, "order-001", 35L, "USD",
                        NOW.minusSeconds(1), "a".repeat(64)));

        assertEquals(Outcome.APPLIED, result.outcome());
        assertEquals(List.of("refund.provider_succeeded.v1", "refund.succeeded"),
                jdbc.outboxEventNames);
        String semantic = jdbc.outboxPayloads.getLast();
        assertTrue(semantic.contains("\"amount_minor\":35"));
        assertTrue(semantic.contains("\"provider_refund_id\":\"pi_001\""));
        assertEquals(1L, jdbc.writes.stream()
                .filter(sql -> sql.startsWith("UPDATE payment_intent")).count(),
                "a successful provider refund may credit the captured payment exactly once");
        assertFalse(jdbc.commitCalled);
    }

    private static ProviderWebhookEffectService service() {
        return new ProviderWebhookEffectService(Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static VerifiedProviderEffectCommand command(EffectKind kind, String order,
            Long amount, String currency, Instant occurredAt, String verificationDigest) {
        return new VerifiedProviderEffectCommand(VerifiedProviderEffectCommand.SCHEMA_V1,
                VerifiedProviderEffectCommand.MAPPING_V1, TENANT, PROJECT, ACCOUNT, "stripe",
                "evt-001", "payment_intent.succeeded", kind, "pi_001", order,
                amount, currency, occurredAt, NOW, verificationDigest, "b".repeat(64),
                "webhook-aaaaaaaaaaaaaaaa");
    }

    private static Map<String, Object> paymentRow(String intentState, String attemptState,
            String operation, long expectedDelta) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("intent_id", INTENT);
        row.put("external_reference", "order-001");
        row.put("amount_minor", 100L);
        row.put("currency", "USD");
        row.put("captured_amount_minor", operation.equals("capture") ? 20L : 0L);
        row.put("refunded_amount_minor", 0L);
        row.put("intent_state", intentState);
        row.put("intent_version", 3L);
        row.put("attempt_id", ATTEMPT);
        row.put("operation", operation);
        row.put("sequence", 2);
        row.put("attempt_state", attemptState);
        row.put("expected_delta_minor", operation.equals("capture") ? expectedDelta : null);
        row.put("expected_currency", operation.equals("capture") ? "USD" : null);
        row.put("business_order_digest", operation.equals("capture")
                ? ProviderEffectExpectationService.businessOrderDigest("order-001") : null);
        return row;
    }

    private static Map<String, Object> application(String digest, String canonical) {
        return Map.of("verification_digest", digest, "canonical_payload_sha256", canonical,
                "target_type", "payment", "target_id", INTENT, "outcome", "APPLIED");
    }

    private static Map<String, Object> refundRow() {
        return Map.ofEntries(
                Map.entry("refund_id", ATTEMPT),
                Map.entry("payment_intent_id", INTENT),
                Map.entry("provider_payment_id", "pi_original"),
                Map.entry("amount_minor", 35L),
                Map.entry("currency", "USD"),
                Map.entry("refund_state", "processing"),
                Map.entry("refund_version", 2L),
                Map.entry("external_reference", "order-001"),
                Map.entry("captured_amount_minor", 100L),
                Map.entry("refunded_amount_minor", 0L),
                Map.entry("intent_version", 3L));
    }

    private static final class FakeJdbc implements InvocationHandler {
        private String tenantScope = TENANT.toString();
        private List<Map<String, Object>> paymentRows;
        private List<Map<String, Object>> refundRows;
        private Map<String, Object> existingApplication;
        private Map<String, Object> targetClock;
        private final List<String> writes = new ArrayList<>();
        private final List<String> outboxEventNames = new ArrayList<>();
        private final List<String> outboxPayloads = new ArrayList<>();
        private boolean commitCalled;
        private boolean rollbackCalled;
        private final Connection connection;

        private FakeJdbc() {
            connection = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, this);
        }

        static FakeJdbc payment() {
            FakeJdbc result = new FakeJdbc();
            result.paymentRows = List.of(paymentRow("created", "pending", "payment", 0));
            return result;
        }

        static FakeJdbc refund() {
            FakeJdbc result = new FakeJdbc();
            result.refundRows = List.of(refundRow());
            return result;
        }

        Connection connection() {
            return connection;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) {
            return switch (method.getName()) {
                case "getAutoCommit" -> false;
                case "prepareStatement" -> statement((String) arguments[0]);
                case "commit" -> { commitCalled = true; yield null; }
                case "rollback" -> { rollbackCalled = true; yield null; }
                case "close" -> null;
                case "isClosed" -> false;
                case "toString" -> "FakeCallerOwnedConnection";
                default -> primitiveDefault(method.getReturnType());
            };
        }

        private PreparedStatement statement(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            InvocationHandler handler = (proxy, method, arguments) -> switch (method.getName()) {
                case "setString", "setLong", "setInt", "setTimestamp", "setObject" -> {
                    parameters.put((Integer) arguments[0], arguments[1]);
                    yield null;
                }
                case "executeQuery" -> resultSet(query(sql, parameters));
                case "executeUpdate" -> {
                    writes.add(normalize(sql));
                    yield 1;
                }
                case "execute" -> true;
                case "close" -> null;
                case "toString" -> "FakePreparedStatement";
                default -> primitiveDefault(method.getReturnType());
            };
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, handler);
        }

        private List<Map<String, Object>> query(String sql, Map<Integer, Object> parameters) {
            String normalized = normalize(sql);
            if (normalized.startsWith("SELECT current_setting")) {
                return List.of(Map.of("1", tenantScope));
            }
            if (normalized.startsWith("SELECT verification_digest")) {
                return existingApplication == null ? List.of() : List.of(existingApplication);
            }
            if (normalized.contains("FROM payment_attempt pa")) {
                return paymentRows;
            }
            if (normalized.contains("FROM refund r")) {
                return refundRows;
            }
            if (normalized.startsWith("SELECT last_provider_occurred_at")) {
                return targetClock == null ? List.of() : List.of(targetClock);
            }
            if (normalized.startsWith("INSERT INTO event_aggregate_revision")) {
                writes.add(normalized);
                return List.of(Map.of("1", 1L, "current_revision", 1L));
            }
            if (normalized.startsWith("INSERT INTO outbox_event")) {
                writes.add(normalized);
                outboxEventNames.add((String) parameters.get(6));
                outboxPayloads.add((String) parameters.get(9));
                return List.of(Map.of("recorded_at", Timestamp.from(NOW)));
            }
            throw new AssertionError("unexpected query: " + normalized);
        }

        private ResultSet resultSet(List<Map<String, Object>> rows) {
            final class Cursor implements InvocationHandler {
                int index = -1;
                boolean wasNull;

                @Override
                public Object invoke(Object proxy, Method method, Object[] arguments) {
                    return switch (method.getName()) {
                        case "next" -> ++index < rows.size();
                        case "getString" -> {
                            Object value = value(arguments[0]);
                            wasNull = value == null;
                            yield value == null ? null : value.toString();
                        }
                        case "getLong" -> {
                            Object value = value(arguments[0]);
                            wasNull = value == null;
                            yield value == null ? 0L : ((Number) value).longValue();
                        }
                        case "getInt" -> {
                            Object value = value(arguments[0]);
                            wasNull = value == null;
                            yield value == null ? 0 : ((Number) value).intValue();
                        }
                        case "getTimestamp" -> {
                            Object value = value(arguments[0]);
                            wasNull = value == null;
                            yield value instanceof Instant instant ? Timestamp.from(instant) : value;
                        }
                        case "getObject" -> {
                            Object value = value(arguments[0]);
                            wasNull = value == null;
                            yield value;
                        }
                        case "wasNull" -> wasNull;
                        case "close" -> null;
                        default -> primitiveDefault(method.getReturnType());
                    };
                }

                private Object value(Object column) {
                    Map<String, Object> row = rows.get(index);
                    return row.get(column instanceof Integer number
                            ? Integer.toString(number) : column.toString());
                }
            }
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, new Cursor());
        }

        private static String normalize(String sql) {
            return sql.strip().replaceAll("\\s+", " ");
        }

        private static Object primitiveDefault(Class<?> type) {
            if (!type.isPrimitive()) {
                return null;
            }
            if (type == boolean.class) {
                return false;
            }
            if (type == int.class) {
                return 0;
            }
            if (type == long.class) {
                return 0L;
            }
            return null;
        }
    }
}
