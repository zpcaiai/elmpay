package com.elmpay.payment;

import com.elmpay.payment.VerifiedProviderEffectCommand.EffectKind;
import com.elmpay.payment.events.SemanticOutboxAppender;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Applies a verified, explicitly mapped provider effect inside a caller-owned transaction.
 *
 * <p>This service deliberately has no dependency on webhook ingress and performs no network I/O.
 * The caller owns commit/rollback. Payment/refund mutation, semantic outbox append and the
 * provider-effect application fact therefore share the inbox processor transaction.
 */
public final class ProviderWebhookEffectService {
    private static final String PAYMENT_BINDING_SQL = """
            SELECT pi.id AS intent_id, pi.project_id, pi.external_reference,
                   pi.amount_minor, pi.currency, pi.captured_amount_minor,
                   pi.refunded_amount_minor, pi.state AS intent_state, pi.version AS intent_version,
                   pa.id AS attempt_id, pa.operation, pa.sequence,
                   pa.state AS attempt_state, pa.provider_transaction_id,
                   expectation.expected_delta_minor, expectation.currency AS expected_currency,
                   expectation.business_order_digest
              FROM payment_attempt pa
              JOIN payment_intent pi
                ON pi.tenant_id = pa.tenant_id AND pi.id = pa.payment_intent_id
              JOIN provider_account account
                ON account.tenant_id = pi.tenant_id
               AND account.project_id = pi.project_id
               AND account.merchant_id = pi.merchant_id
               AND account.id = pa.provider_account_id
               AND account.provider = pa.provider
              LEFT JOIN provider_effect_expectation expectation
                ON expectation.tenant_id = pa.tenant_id
               AND expectation.payment_attempt_id = pa.id
             WHERE pi.tenant_id = ?::uuid AND pi.project_id = ?::uuid
               AND pa.provider_account_id = ?::uuid AND pa.provider = ?
               AND pa.provider_transaction_id = ?
             ORDER BY pa.sequence DESC
             LIMIT 9
             FOR UPDATE OF pi, pa
            """;
    private static final String REFUND_BINDING_SQL = """
            SELECT r.id AS refund_id, r.project_id, r.payment_intent_id,
                   r.provider_payment_id, r.amount_minor, r.currency, r.state AS refund_state,
                   r.version AS refund_version, pi.external_reference,
                   pi.captured_amount_minor, pi.refunded_amount_minor,
                   pi.version AS intent_version
              FROM refund r
              JOIN payment_intent pi
                ON pi.tenant_id = r.tenant_id AND pi.id = r.payment_intent_id
              JOIN provider_account account
                ON account.tenant_id = r.tenant_id
               AND account.project_id = r.project_id
               AND account.merchant_id = pi.merchant_id
               AND account.id = r.provider_account_id
               AND account.provider = r.provider
             WHERE r.tenant_id = ?::uuid AND r.project_id = ?::uuid
               AND r.provider_account_id = ?::uuid AND r.provider = ?
               AND r.provider_refund_id = ?
             LIMIT 3
             FOR UPDATE OF r, pi
            """;
    private static final String EXISTING_APPLICATION_SQL = """
            SELECT verification_digest, canonical_payload_sha256, target_type, target_id, outcome
              FROM provider_effect_application
             WHERE tenant_id = ?::uuid AND provider = ?
               AND provider_account_id = ?::uuid AND provider_event_id = ?
            """;
    private static final String TARGET_CLOCK_SQL = """
            SELECT last_provider_occurred_at, last_provider_event_id, last_effect_kind
              FROM provider_effect_target_clock
             WHERE tenant_id = ?::uuid AND target_type = ? AND target_id = ?::uuid
             FOR UPDATE
            """;
    private static final String UPSERT_TARGET_CLOCK_SQL = """
            INSERT INTO provider_effect_target_clock
              (tenant_id, target_type, target_id, last_provider_occurred_at,
               last_provider_event_id, last_effect_kind, updated_at)
            VALUES (?::uuid, ?, ?::uuid, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, target_type, target_id) DO UPDATE
               SET last_provider_occurred_at = EXCLUDED.last_provider_occurred_at,
                   last_provider_event_id = EXCLUDED.last_provider_event_id,
                   last_effect_kind = EXCLUDED.last_effect_kind,
                   updated_at = EXCLUDED.updated_at
             WHERE provider_effect_target_clock.last_provider_occurred_at
                    <= EXCLUDED.last_provider_occurred_at
            """;
    private static final String INSERT_APPLICATION_SQL = """
            INSERT INTO provider_effect_application
              (tenant_id, project_id, provider_account_id, provider, provider_event_id,
               provider_event_type, mapping_version, verification_digest,
               canonical_payload_sha256, target_type, target_id, outcome,
               provider_occurred_at, applied_at)
            VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?::uuid, ?, ?, ?)
            """;

    public enum Outcome {
        APPLIED,
        DUPLICATE,
        NOOP_DUPLICATE_STATE,
        NOOP_OUT_OF_ORDER,
        NOOP_OBSERVATION
    }

    public record Result(Outcome outcome, String targetType, UUID targetId,
            UUID semanticEventId, Long semanticRevision) {
        public Result {
            Objects.requireNonNull(outcome, "outcome");
            if (!List.of("payment", "refund").contains(targetType)) {
                throw new IllegalArgumentException("targetType is invalid");
            }
            Objects.requireNonNull(targetId, "targetId");
            if ((semanticEventId == null) != (semanticRevision == null)) {
                throw new IllegalArgumentException("semantic event identity is incomplete");
            }
        }
    }

    /** Safe-code rejection consumed by the webhook processor retry classifier. */
    public static final class EffectRejectedException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final String failureCode;
        private final boolean permanent;

        public EffectRejectedException(String failureCode, boolean permanent, String message) {
            super(message);
            if (failureCode == null || !failureCode.matches("[A-Z][A-Z0-9_]{2,79}")) {
                throw new IllegalArgumentException("failureCode has an invalid format");
            }
            this.failureCode = failureCode;
            this.permanent = permanent;
        }

        public EffectRejectedException(String failureCode, boolean permanent, String message,
                Throwable cause) {
            super(message, cause);
            if (failureCode == null || !failureCode.matches("[A-Z][A-Z0-9_]{2,79}")) {
                throw new IllegalArgumentException("failureCode has an invalid format");
            }
            this.failureCode = failureCode;
            this.permanent = permanent;
        }

        public String failureCode() {
            return failureCode;
        }

        public boolean permanent() {
            return permanent;
        }
    }

    private final Clock clock;

    public ProviderWebhookEffectService(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Result apply(Connection connection, VerifiedProviderEffectCommand command) {
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(command, "command");
        try {
            requireCallerTransaction(connection);
            requireTenantScope(connection, command.tenantId());
            serializeEvent(connection, command);
            ExistingApplication existing = existingApplication(connection, command);
            if (existing != null) {
                requireSameApplication(existing, command);
                return new Result(Outcome.DUPLICATE, existing.targetType(), existing.targetId(),
                        null, null);
            }
            return command.effectKind().refund()
                    ? applyRefund(connection, command)
                    : applyPayment(connection, command);
        } catch (EffectRejectedException rejection) {
            throw rejection;
        } catch (SQLException failure) {
            throw databaseFailure(failure);
        } catch (ArithmeticException failure) {
            throw reject("PROVIDER_EFFECT_AMOUNT_OVERFLOW",
                    "provider effect amount arithmetic overflow", failure);
        }
    }

    private Result applyPayment(Connection connection, VerifiedProviderEffectCommand command)
            throws SQLException {
        PaymentBinding binding = paymentBinding(connection, command);
        TargetClock targetClock = targetClock(connection, command.tenantId(), "payment",
                binding.intentId());
        if (isNonTerminalOutOfOrder(command.effectKind(), command.providerOccurredAt(),
                targetClock)) {
            return recordNoop(connection, command, "payment", binding.intentId(),
                    Outcome.NOOP_OUT_OF_ORDER);
        }

        PaymentMutation mutation = paymentMutation(binding, command);
        if (mutation.terminalConflict()) {
            throw reject("PROVIDER_EFFECT_TERMINAL_CONFLICT",
                    "provider callback conflicts with an immutable terminal payment state");
        }
        if (mutation.attemptConflict()) {
            throw reject("PROVIDER_EFFECT_ATTEMPT_CONFLICT",
                    "provider callback conflicts with an immutable provider attempt outcome");
        }
        if (!mutation.intentChanged() && !mutation.attemptChanged()) {
            advanceClock(connection, command, "payment", binding.intentId(), targetClock);
            Outcome noop = command.effectKind() == EffectKind.PAYMENT_PENDING
                    ? Outcome.NOOP_OBSERVATION : Outcome.NOOP_DUPLICATE_STATE;
            return recordNoop(connection, command, "payment", binding.intentId(), noop);
        }
        updatePayment(connection, binding, mutation, command);
        updateAttempt(connection, binding, mutation, command);
        SemanticOutboxAppender.AppendResult internalEvent = appendPaymentEvent(connection, command,
                binding, mutation);
        SemanticOutboxAppender.AppendResult event = command.effectKind()
                == EffectKind.PAYMENT_CAPTURED
                        ? appendCapturedEvent(connection, command, binding, mutation)
                        : internalEvent;
        advanceClock(connection, command, "payment", binding.intentId(), targetClock);
        insertApplication(connection, command, "payment", binding.intentId(), "APPLIED");
        return new Result(Outcome.APPLIED, "payment", binding.intentId(), event.eventId(),
                event.revision());
    }

    private Result applyRefund(Connection connection, VerifiedProviderEffectCommand command)
            throws SQLException {
        RefundBinding binding = refundBinding(connection, command);
        TargetClock targetClock = targetClock(connection, command.tenantId(), "refund",
                binding.refundId());
        if (command.effectKind() == EffectKind.REFUND_PENDING
                && isOlder(command.providerOccurredAt(), targetClock)) {
            return recordNoop(connection, command, "refund", binding.refundId(),
                    Outcome.NOOP_OUT_OF_ORDER);
        }
        RefundMutation mutation = refundMutation(binding, command);
        if (mutation.terminalConflict()) {
            throw reject("PROVIDER_EFFECT_TERMINAL_CONFLICT",
                    "provider callback conflicts with an immutable terminal refund state");
        }
        if (!mutation.changed()) {
            advanceClock(connection, command, "refund", binding.refundId(), targetClock);
            Outcome noop = command.effectKind() == EffectKind.REFUND_PENDING
                    ? Outcome.NOOP_OBSERVATION : Outcome.NOOP_DUPLICATE_STATE;
            return recordNoop(connection, command, "refund", binding.refundId(), noop);
        }
        if (mutation.creditPayment()) {
            creditSuccessfulRefund(connection, binding, command);
        }
        updateRefund(connection, binding, mutation, command);
        SemanticOutboxAppender.AppendResult internalEvent = appendRefundEvent(connection, command,
                binding, mutation);
        SemanticOutboxAppender.AppendResult event = command.effectKind()
                == EffectKind.REFUND_SUCCEEDED
                        ? appendRefundSucceededEvent(connection, command, binding)
                        : internalEvent;
        advanceClock(connection, command, "refund", binding.refundId(), targetClock);
        insertApplication(connection, command, "refund", binding.refundId(), "APPLIED");
        return new Result(Outcome.APPLIED, "refund", binding.refundId(), event.eventId(),
                event.revision());
    }

    private static PaymentBinding paymentBinding(Connection connection,
            VerifiedProviderEffectCommand command) throws SQLException {
        List<PaymentBinding> rows = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(PAYMENT_BINDING_SQL)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.projectId().toString());
            statement.setString(3, command.providerAccountId().toString());
            statement.setString(4, command.provider());
            statement.setString(5, command.providerPaymentId());
            try (ResultSet row = statement.executeQuery()) {
                while (row.next()) {
                    rows.add(paymentBinding(row));
                }
            }
        }
        if (rows.isEmpty() || rows.size() > 8) {
            throw reject("PROVIDER_EFFECT_PAYMENT_BINDING_MISSING",
                    "provider object is not bound to one payment");
        }
        UUID intentId = rows.getFirst().intentId();
        if (rows.stream().anyMatch(row -> !intentId.equals(row.intentId())
                || !command.businessOrderNo().equals(row.externalReference()))) {
            throw reject("PROVIDER_EFFECT_PAYMENT_BINDING_CONFLICT",
                    "provider object, business order and payment scope are not uniquely bound");
        }
        return choosePaymentAttempt(rows, command);
    }

    private static PaymentBinding choosePaymentAttempt(List<PaymentBinding> rows,
            VerifiedProviderEffectCommand command) {
        List<PaymentBinding> matching = rows.stream().filter(row -> switch (command.effectKind()) {
            case PAYMENT_CAPTURED -> captureMatches(row, command);
            case PAYMENT_CANCELED -> row.operation().equals("cancel")
                    || row.operation().equals("close") || row.operation().equals("payment");
            case PAYMENT_PENDING, PAYMENT_AUTHORIZED, PAYMENT_FAILED ->
                    row.operation().equals("payment");
            default -> false;
        }).toList();
        if (command.effectKind() == EffectKind.PAYMENT_CAPTURED) {
            List<PaymentBinding> expectedCapture = matching.stream()
                    .filter(row -> row.operation().equals("capture")).toList();
            if (expectedCapture.size() == 1) {
                return expectedCapture.getFirst();
            }
            if (expectedCapture.size() > 1) {
                throw reject("PROVIDER_EFFECT_CAPTURE_BINDING_AMBIGUOUS",
                        "capture callback matches multiple immutable capture expectations");
            }
        }
        List<PaymentBinding> preferred = command.effectKind() == EffectKind.PAYMENT_CANCELED
                ? matching.stream().filter(row -> row.operation().equals("cancel")
                        || row.operation().equals("close")).toList()
                : matching;
        if (preferred.isEmpty() && command.effectKind() == EffectKind.PAYMENT_CANCELED) {
            preferred = matching.stream().filter(row -> row.operation().equals("payment")).toList();
        }
        if (preferred.isEmpty()) {
            throw reject("PROVIDER_EFFECT_PAYMENT_BINDING_MISSING",
                    "provider event has no compatible payment attempt");
        }
        // Recovery attempts may share one provider object. They still bind one payment; update the
        // latest durable attempt while the aggregate lock prevents duplicate financial effects.
        return preferred.getFirst();
    }

    private static boolean captureMatches(PaymentBinding row,
            VerifiedProviderEffectCommand command) {
        if (command.amountMinor() == null || !row.currency().equals(command.currency())) {
            return false;
        }
        if (row.operation().equals("capture")) {
            return row.expectedDeltaMinor() != null
                    && row.expectedDeltaMinor().equals(command.amountMinor())
                    && command.currency().equals(row.expectedCurrency())
                    && ProviderEffectExpectationService.businessOrderDigest(
                            command.businessOrderNo()).equals(row.businessOrderDigest());
        }
        return row.operation().equals("payment")
                && command.amountMinor() == row.amountMinor();
    }

    private static RefundBinding refundBinding(Connection connection,
            VerifiedProviderEffectCommand command) throws SQLException {
        List<RefundBinding> rows = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(REFUND_BINDING_SQL)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.projectId().toString());
            statement.setString(3, command.providerAccountId().toString());
            statement.setString(4, command.provider());
            statement.setString(5, command.providerPaymentId());
            try (ResultSet row = statement.executeQuery()) {
                while (row.next()) {
                    rows.add(refundBinding(row));
                }
            }
        }
        if (rows.size() != 1) {
            throw reject("PROVIDER_EFFECT_REFUND_BINDING_CONFLICT",
                    "provider refund is not bound to one durable refund");
        }
        RefundBinding binding = rows.getFirst();
        if (!command.businessOrderNo().equals(binding.externalReference())
                || command.amountMinor() == null
                || command.amountMinor() != binding.amountMinor()
                || !command.currency().equals(binding.currency())) {
            throw reject("PROVIDER_EFFECT_REFUND_FACT_MISMATCH",
                    "provider refund money or business binding differs from immutable facts");
        }
        return binding;
    }

    private static PaymentMutation paymentMutation(PaymentBinding binding,
            VerifiedProviderEffectCommand command) {
        String state = binding.intentState();
        boolean terminal = List.of("captured", "failed", "canceled", "expired").contains(state);
        String nextState = state;
        long nextCaptured = binding.capturedAmountMinor();
        switch (command.effectKind()) {
            case PAYMENT_PENDING -> {
                requireOptionalPaymentMoney(binding, command);
            }
            case PAYMENT_AUTHORIZED -> {
                requireFullPaymentMoney(binding, command);
                nextState = "authorized";
            }
            case PAYMENT_CAPTURED -> {
                long delta = binding.operation().equals("capture")
                        ? command.amountMinor()
                        : Math.subtractExact(binding.amountMinor(), binding.capturedAmountMinor());
                if (delta <= 0 || command.amountMinor() == null
                        || !binding.currency().equals(command.currency())) {
                    throw reject("PROVIDER_EFFECT_CAPTURE_FACT_MISMATCH",
                            "capture callback does not match immutable capture money");
                }
                nextCaptured = Math.addExact(binding.capturedAmountMinor(), delta);
                if (nextCaptured > binding.amountMinor()) {
                    throw reject("PROVIDER_EFFECT_CAPTURE_EXCEEDS_AUTHORIZED",
                            "capture callback would exceed payment amount");
                }
                nextState = nextCaptured == binding.amountMinor() ? "captured" : "authorized";
            }
            case PAYMENT_FAILED -> {
                requireOptionalPaymentMoney(binding, command);
                nextState = "failed";
            }
            case PAYMENT_CANCELED -> {
                requireOptionalPaymentMoney(binding, command);
                nextState = "canceled";
            }
            default -> throw reject("PROVIDER_EFFECT_MAPPING_INVALID",
                    "refund effect was routed to payment mutation");
        }
        boolean terminalConflict = terminal && !state.equals(nextState);
        String desiredAttempt = switch (command.effectKind()) {
            case PAYMENT_PENDING -> binding.attemptState();
            case PAYMENT_AUTHORIZED, PAYMENT_CAPTURED -> "succeeded";
            case PAYMENT_FAILED, PAYMENT_CANCELED -> "failed";
            default -> binding.attemptState();
        };
        boolean attemptFinal = List.of("succeeded", "failed").contains(binding.attemptState());
        boolean attemptConflict = attemptFinal && !binding.attemptState().equals(desiredAttempt);
        return new PaymentMutation(nextState, nextCaptured, !state.equals(nextState)
                || nextCaptured != binding.capturedAmountMinor(), desiredAttempt,
                !binding.attemptState().equals(desiredAttempt), terminalConflict, attemptConflict);
    }

    private static RefundMutation refundMutation(RefundBinding binding,
            VerifiedProviderEffectCommand command) {
        String next = switch (command.effectKind()) {
            case REFUND_PENDING -> List.of("requested", "approved", "approval_pending")
                    .contains(binding.refundState()) ? "processing" : binding.refundState();
            case REFUND_SUCCEEDED -> "succeeded";
            case REFUND_FAILED -> "failed";
            case REFUND_CANCELED -> "canceled";
            default -> throw reject("PROVIDER_EFFECT_MAPPING_INVALID",
                    "payment effect was routed to refund mutation");
        };
        boolean terminal = List.of("succeeded", "failed", "canceled",
                "partially_succeeded").contains(binding.refundState());
        boolean conflict = terminal && !binding.refundState().equals(next);
        return new RefundMutation(next, !binding.refundState().equals(next), conflict,
                "succeeded".equals(next) && !"succeeded".equals(binding.refundState()));
    }

    private static void updatePayment(Connection connection, PaymentBinding binding,
            PaymentMutation mutation, VerifiedProviderEffectCommand command) throws SQLException {
        if (!mutation.intentChanged()) {
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE payment_intent
                   SET state = ?, captured_amount_minor = ?, updated_at = ?, version = version + 1
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND id = ?::uuid
                   AND version = ? AND captured_amount_minor = ? AND state = ?
                """)) {
            statement.setString(1, mutation.nextIntentState());
            statement.setLong(2, mutation.nextCapturedAmountMinor());
            statement.setTimestamp(3, Timestamp.from(command.verifiedAt()));
            statement.setString(4, command.tenantId().toString());
            statement.setString(5, command.projectId().toString());
            statement.setString(6, binding.intentId().toString());
            statement.setLong(7, binding.intentVersion());
            statement.setLong(8, binding.capturedAmountMinor());
            statement.setString(9, binding.intentState());
            requireOne(statement.executeUpdate(), "PROVIDER_EFFECT_PAYMENT_CONCURRENT",
                    "payment changed while applying provider callback");
        }
    }

    private static void updateAttempt(Connection connection, PaymentBinding binding,
            PaymentMutation mutation, VerifiedProviderEffectCommand command) throws SQLException {
        if (!mutation.attemptChanged()) {
            return;
        }
        String outcome = "succeeded".equals(mutation.nextAttemptState())
                ? "succeeded" : "failed_final";
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE payment_attempt
                   SET state = ?, outcome_class = ?, response_digest = ?, provider_request_id = ?,
                       provider_code_namespace = ?, provider_code = ?, settled_at = ?
                 WHERE tenant_id = ?::uuid AND id = ?::uuid AND state = ?
                """)) {
            statement.setString(1, mutation.nextAttemptState());
            statement.setString(2, outcome);
            statement.setString(3, command.verificationDigest());
            statement.setString(4, command.providerEventId());
            statement.setString(5, "webhook." + command.provider());
            statement.setString(6, command.providerEventType());
            statement.setTimestamp(7, Timestamp.from(command.providerOccurredAt()));
            statement.setString(8, command.tenantId().toString());
            statement.setString(9, binding.attemptId().toString());
            statement.setString(10, binding.attemptState());
            requireOne(statement.executeUpdate(), "PROVIDER_EFFECT_ATTEMPT_CONCURRENT",
                    "payment attempt changed while applying provider callback");
        }
    }

    private static void creditSuccessfulRefund(Connection connection, RefundBinding binding,
            VerifiedProviderEffectCommand command) throws SQLException {
        long nextRefunded = Math.addExact(binding.refundedAmountMinor(), binding.amountMinor());
        if (nextRefunded > binding.capturedAmountMinor()) {
            throw reject("PROVIDER_EFFECT_REFUND_EXCEEDS_CAPTURED",
                    "successful refund would exceed captured payment amount");
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE payment_intent
                   SET refunded_amount_minor = ?, updated_at = ?, version = version + 1
                 WHERE tenant_id = ?::uuid AND id = ?::uuid AND version = ?
                   AND refunded_amount_minor = ? AND ? <= captured_amount_minor
                """)) {
            statement.setLong(1, nextRefunded);
            statement.setTimestamp(2, Timestamp.from(command.verifiedAt()));
            statement.setString(3, command.tenantId().toString());
            statement.setString(4, binding.paymentIntentId().toString());
            statement.setLong(5, binding.intentVersion());
            statement.setLong(6, binding.refundedAmountMinor());
            statement.setLong(7, nextRefunded);
            requireOne(statement.executeUpdate(), "PROVIDER_EFFECT_REFUND_CONCURRENT",
                    "payment changed while applying successful refund");
        }
    }

    private static void updateRefund(Connection connection, RefundBinding binding,
            RefundMutation mutation, VerifiedProviderEffectCommand command) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE refund
                   SET state = ?, provider_outcome_digest = ?, failure_code = ?,
                       correlation_id = ?, updated_at = ?, version = version + 1
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND id = ?::uuid
                   AND version = ? AND state = ?
                """)) {
            statement.setString(1, mutation.nextState());
            statement.setString(2, command.verificationDigest());
            statement.setString(3, mutation.nextState().equals("failed")
                    || mutation.nextState().equals("canceled")
                            ? "PROVIDER_WEBHOOK_" + mutation.nextState().toUpperCase(Locale.ROOT)
                            : null);
            statement.setString(4, command.traceId());
            statement.setTimestamp(5, Timestamp.from(command.verifiedAt()));
            statement.setString(6, command.tenantId().toString());
            statement.setString(7, command.projectId().toString());
            statement.setString(8, binding.refundId().toString());
            statement.setLong(9, binding.refundVersion());
            statement.setString(10, binding.refundState());
            requireOne(statement.executeUpdate(), "PROVIDER_EFFECT_REFUND_CONCURRENT",
                    "refund changed while applying provider callback");
        }
    }

    private static SemanticOutboxAppender.AppendResult appendPaymentEvent(Connection connection,
            VerifiedProviderEffectCommand command, PaymentBinding binding,
            PaymentMutation mutation) throws SQLException {
        Map<String, Object> payload = commonPayload(command);
        payload.put("payment_intent_id", binding.intentId().toString());
        payload.put("state", mutation.nextIntentState());
        payload.put("captured_amount_minor", mutation.nextCapturedAmountMinor());
        payload.put("currency", binding.currency());
        return SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                command.tenantId(), command.projectId(), "payment_intent", binding.intentId(),
                paymentEventName(command, mutation), 1, command.providerOccurredAt(),
                command.traceId(), payload));
    }

    /**
     * Emits the sole ledger-driving capture fact. The legacy state event remains available to
     * older consumers, but only this catalog event carries an exact money delta.
     */
    private static SemanticOutboxAppender.AppendResult appendCapturedEvent(Connection connection,
            VerifiedProviderEffectCommand command, PaymentBinding binding,
            PaymentMutation mutation) throws SQLException {
        long delta = Math.subtractExact(mutation.nextCapturedAmountMinor(),
                binding.capturedAmountMinor());
        if (delta <= 0) {
            throw reject("PROVIDER_EFFECT_CAPTURE_DELTA_INVALID",
                    "capture state changed without a positive money delta");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("payment_intent_id", binding.intentId().toString());
        payload.put("project_id", command.projectId().toString());
        payload.put("provider", command.provider());
        payload.put("captured_at", command.providerOccurredAt().toString());
        payload.put("amount_minor", delta);
        payload.put("currency", binding.currency());
        payload.put("business_order_digest",
                ProviderEffectExpectationService.businessOrderDigest(
                        binding.externalReference()));
        return SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                command.tenantId(), command.projectId(), "payment_intent", binding.intentId(),
                "payment_intent.captured", 1, command.providerOccurredAt(), command.traceId(),
                payload));
    }

    private static SemanticOutboxAppender.AppendResult appendRefundEvent(Connection connection,
            VerifiedProviderEffectCommand command, RefundBinding binding,
            RefundMutation mutation) throws SQLException {
        Map<String, Object> payload = commonPayload(command);
        payload.put("refund_id", binding.refundId().toString());
        payload.put("payment_intent_id", binding.paymentIntentId().toString());
        payload.put("state", mutation.nextState());
        payload.put("amount_minor", binding.amountMinor());
        payload.put("currency", binding.currency());
        return SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                command.tenantId(), command.projectId(), "refund", binding.refundId(),
                "refund.provider_" + mutation.nextState() + ".v1", 1,
                command.providerOccurredAt(), command.traceId(), payload));
    }

    /** Emits the sole ledger-driving refund fact after the durable refund transition succeeds. */
    private static SemanticOutboxAppender.AppendResult appendRefundSucceededEvent(
            Connection connection, VerifiedProviderEffectCommand command, RefundBinding binding)
            throws SQLException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("refund_id", binding.refundId().toString());
        payload.put("payment_intent_id", binding.paymentIntentId().toString());
        payload.put("project_id", command.projectId().toString());
        payload.put("provider", command.provider());
        payload.put("provider_refund_id", command.providerPaymentId());
        payload.put("refunded_at", command.providerOccurredAt().toString());
        payload.put("amount_minor", binding.amountMinor());
        payload.put("currency", binding.currency());
        return SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                command.tenantId(), command.projectId(), "refund", binding.refundId(),
                "refund.succeeded", 1, command.providerOccurredAt(), command.traceId(), payload));
    }

    private static Map<String, Object> commonPayload(VerifiedProviderEffectCommand command) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("provider", command.provider());
        payload.put("provider_account_id", command.providerAccountId().toString());
        payload.put("provider_event_id", command.providerEventId());
        payload.put("provider_event_type", command.providerEventType());
        payload.put("provider_event_mapping", command.mappingVersion());
        payload.put("verification_digest", command.verificationDigest());
        payload.put("canonical_payload_sha256", command.canonicalPayloadSha256());
        return payload;
    }

    private static String paymentEventName(VerifiedProviderEffectCommand command,
            PaymentMutation mutation) {
        if (command.effectKind() == EffectKind.PAYMENT_CAPTURED) {
            return mutation.nextIntentState().equals("captured")
                    ? "payment.captured.v1" : "payment.partially_captured.v1";
        }
        return switch (command.effectKind()) {
            case PAYMENT_AUTHORIZED -> "payment.authorized.v1";
            case PAYMENT_FAILED -> "payment.failed.v1";
            case PAYMENT_CANCELED -> "payment.canceled.v1";
            default -> throw reject("PROVIDER_EFFECT_MAPPING_INVALID",
                    "observation cannot emit a state-change event");
        };
    }

    private static Result recordNoop(Connection connection,
            VerifiedProviderEffectCommand command, String targetType, UUID targetId,
            Outcome outcome) throws SQLException {
        String persisted = switch (outcome) {
            case NOOP_DUPLICATE_STATE -> "NOOP_DUPLICATE_STATE";
            case NOOP_OUT_OF_ORDER -> "NOOP_OUT_OF_ORDER";
            case NOOP_OBSERVATION -> "NOOP_OBSERVATION";
            default -> throw new IllegalArgumentException("outcome is not a no-op");
        };
        insertApplication(connection, command, targetType, targetId, persisted);
        return new Result(outcome, targetType, targetId, null, null);
    }

    private static void insertApplication(Connection connection,
            VerifiedProviderEffectCommand command, String targetType, UUID targetId, String outcome)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT_APPLICATION_SQL)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.projectId().toString());
            statement.setString(3, command.providerAccountId().toString());
            statement.setString(4, command.provider());
            statement.setString(5, command.providerEventId());
            statement.setString(6, command.providerEventType());
            statement.setString(7, command.mappingVersion());
            statement.setString(8, command.verificationDigest());
            statement.setString(9, command.canonicalPayloadSha256());
            statement.setString(10, targetType);
            statement.setString(11, targetId.toString());
            statement.setString(12, outcome);
            statement.setTimestamp(13, Timestamp.from(command.providerOccurredAt()));
            statement.setTimestamp(14, Timestamp.from(command.verifiedAt()));
            requireOne(statement.executeUpdate(), "PROVIDER_EFFECT_APPLICATION_CONCURRENT",
                    "provider effect application was concurrently changed");
        }
    }

    private static ExistingApplication existingApplication(Connection connection,
            VerifiedProviderEffectCommand command) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(EXISTING_APPLICATION_SQL)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.provider());
            statement.setString(3, command.providerAccountId().toString());
            statement.setString(4, command.providerEventId());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) {
                    return null;
                }
                ExistingApplication result = new ExistingApplication(
                        row.getString("verification_digest"),
                        row.getString("canonical_payload_sha256"),
                        row.getString("target_type"), row.getObject("target_id", UUID.class),
                        row.getString("outcome"));
                if (row.next()) {
                    throw reject("PROVIDER_EFFECT_IDENTITY_CONFLICT",
                            "provider event identity is not unique");
                }
                return result;
            }
        }
    }

    private static void requireSameApplication(ExistingApplication existing,
            VerifiedProviderEffectCommand command) {
        if (!existing.verificationDigest().equals(command.verificationDigest())
                || !existing.canonicalPayloadSha256().equals(
                        command.canonicalPayloadSha256())) {
            throw reject("PROVIDER_EFFECT_IDENTITY_CONFLICT",
                    "provider event id was reused with different verified content");
        }
    }

    private static TargetClock targetClock(Connection connection, UUID tenantId,
            String targetType, UUID targetId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(TARGET_CLOCK_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, targetType);
            statement.setString(3, targetId.toString());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) {
                    return null;
                }
                TargetClock result = new TargetClock(
                        row.getTimestamp("last_provider_occurred_at").toInstant(),
                        row.getString("last_provider_event_id"),
                        row.getString("last_effect_kind"));
                if (row.next()) {
                    throw reject("PROVIDER_EFFECT_TARGET_CLOCK_CONFLICT",
                            "provider effect target clock is not unique");
                }
                return result;
            }
        }
    }

    private void advanceClock(Connection connection, VerifiedProviderEffectCommand command,
            String targetType, UUID targetId, TargetClock current) throws SQLException {
        if (isOlder(command.providerOccurredAt(), current)) {
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement(UPSERT_TARGET_CLOCK_SQL)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, targetType);
            statement.setString(3, targetId.toString());
            statement.setTimestamp(4, Timestamp.from(command.providerOccurredAt()));
            statement.setString(5, command.providerEventId());
            statement.setString(6, command.effectKind().name());
            statement.setTimestamp(7, Timestamp.from(clock.instant()));
            statement.executeUpdate();
        }
    }

    private static boolean isNonTerminalOutOfOrder(EffectKind kind, Instant occurredAt,
            TargetClock clock) {
        return (kind == EffectKind.PAYMENT_PENDING || kind == EffectKind.PAYMENT_AUTHORIZED)
                && isOlder(occurredAt, clock);
    }

    private static boolean isOlder(Instant occurredAt, TargetClock clock) {
        return clock != null && occurredAt.isBefore(clock.occurredAt());
    }

    private static void serializeEvent(Connection connection,
            VerifiedProviderEffectCommand command) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")) {
            statement.setString(1, command.tenantId() + ":" + command.provider() + ":"
                    + command.providerAccountId() + ":" + command.providerEventId());
            statement.execute();
        }
    }

    private static void requireTenantScope(Connection connection, UUID tenantId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT current_setting('app.tenant_id', true)");
                ResultSet result = statement.executeQuery()) {
            if (!result.next() || !tenantId.toString().equals(result.getString(1))
                    || result.next()) {
                throw reject("PROVIDER_EFFECT_TENANT_SCOPE_MISMATCH",
                        "caller transaction tenant does not match verified provider effect");
            }
        }
    }

    private static void requireCallerTransaction(Connection connection) throws SQLException {
        if (connection.getAutoCommit()) {
            throw reject("PROVIDER_EFFECT_TRANSACTION_REQUIRED",
                    "verified provider effect requires a caller-owned transaction");
        }
    }

    private static void requireFullPaymentMoney(PaymentBinding binding,
            VerifiedProviderEffectCommand command) {
        if (command.amountMinor() == null || command.amountMinor() != binding.amountMinor()
                || !binding.currency().equals(command.currency())) {
            throw reject("PROVIDER_EFFECT_PAYMENT_FACT_MISMATCH",
                    "provider callback money differs from immutable payment facts");
        }
    }

    private static void requireOptionalPaymentMoney(PaymentBinding binding,
            VerifiedProviderEffectCommand command) {
        if (command.amountMinor() != null && (command.amountMinor() != binding.amountMinor()
                || !binding.currency().equals(command.currency()))) {
            throw reject("PROVIDER_EFFECT_PAYMENT_FACT_MISMATCH",
                    "provider callback money differs from immutable payment facts");
        }
    }

    private static PaymentBinding paymentBinding(ResultSet row) throws SQLException {
        long expected = row.getLong("expected_delta_minor");
        Long expectedDelta = row.wasNull() ? null : expected;
        return new PaymentBinding(row.getObject("intent_id", UUID.class),
                row.getString("external_reference"), row.getLong("amount_minor"),
                row.getString("currency"), row.getLong("captured_amount_minor"),
                row.getLong("refunded_amount_minor"), row.getString("intent_state"),
                row.getLong("intent_version"), row.getObject("attempt_id", UUID.class),
                row.getString("operation"), row.getInt("sequence"),
                row.getString("attempt_state"), expectedDelta,
                row.getString("expected_currency"), row.getString("business_order_digest"));
    }

    private static RefundBinding refundBinding(ResultSet row) throws SQLException {
        return new RefundBinding(row.getObject("refund_id", UUID.class),
                row.getObject("payment_intent_id", UUID.class),
                row.getString("provider_payment_id"), row.getLong("amount_minor"),
                row.getString("currency"), row.getString("refund_state"),
                row.getLong("refund_version"), row.getString("external_reference"),
                row.getLong("captured_amount_minor"), row.getLong("refunded_amount_minor"),
                row.getLong("intent_version"));
    }

    private static void requireOne(int count, String code, String message) {
        if (count != 1) {
            throw new EffectRejectedException(code, false, message);
        }
    }

    private static EffectRejectedException reject(String code, String message) {
        return new EffectRejectedException(code, true, message);
    }

    private static EffectRejectedException reject(String code, String message, Throwable cause) {
        return new EffectRejectedException(code, true, message, cause);
    }

    private static EffectRejectedException databaseFailure(SQLException failure) {
        String state = failure.getSQLState();
        boolean retryable = state == null || state.startsWith("08") || state.startsWith("40")
                || "55P03".equals(state) || "57014".equals(state);
        return new EffectRejectedException(retryable
                ? "PROVIDER_EFFECT_DATABASE_RETRYABLE" : "PROVIDER_EFFECT_DATABASE_REJECTED",
                !retryable, "provider effect database operation failed closed", failure);
    }

    private record PaymentBinding(UUID intentId, String externalReference, long amountMinor,
            String currency, long capturedAmountMinor, long refundedAmountMinor,
            String intentState, long intentVersion, UUID attemptId, String operation,
            int sequence, String attemptState, Long expectedDeltaMinor, String expectedCurrency,
            String businessOrderDigest) {
    }

    private record RefundBinding(UUID refundId, UUID paymentIntentId, String providerPaymentId,
            long amountMinor, String currency, String refundState, long refundVersion,
            String externalReference, long capturedAmountMinor, long refundedAmountMinor,
            long intentVersion) {
    }

    private record PaymentMutation(String nextIntentState, long nextCapturedAmountMinor,
            boolean intentChanged, String nextAttemptState, boolean attemptChanged,
            boolean terminalConflict, boolean attemptConflict) {
    }

    private record RefundMutation(String nextState, boolean changed, boolean terminalConflict,
            boolean creditPayment) {
    }

    private record ExistingApplication(String verificationDigest, String canonicalPayloadSha256,
            String targetType, UUID targetId, String outcome) {
    }

    private record TargetClock(Instant occurredAt, String providerEventId, String effectKind) {
    }
}
