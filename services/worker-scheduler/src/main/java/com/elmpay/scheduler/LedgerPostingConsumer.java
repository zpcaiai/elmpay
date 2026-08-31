package com.elmpay.scheduler;

import com.elmpay.ledger.LedgerService;
import com.elmpay.scheduler.events.JdbcEventDeliveryStore;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Durable financial consumer: revision guard, inbox marker and ledger posting share one commit. */
public final class LedgerPostingConsumer {
    private static final String CONSUMER_NAME = "immutable-ledger-v2";
    private static final Set<String> FINANCIAL_EVENTS = Set.of(
            "payment_intent.captured", "refund.succeeded");
    /**
     * Versioned state/attempt events produced before the catalog money facts were introduced.
     * They advance aggregate ordering but can never post money. This is an explicit allowlist so
     * an arbitrary name ending in {@code .v1} cannot bypass posting-policy enforcement.
     */
    private static final Set<String> LEGACY_INTERNAL_EVENTS = Set.of(
            "billing.dunning.opened.v1", "billing.dunning.result.v1",
            "billing.dunning.retry_due.v1", "billing.mandate.created.v1",
            "billing.mandate.revoked.v1", "billing.plan.created.v1",
            "billing.subscription.adjusted.v1", "billing.subscription.created.v1",
            "billing.subscription.renewal_due.v1",
            "billing.subscription.renewal_result.v1",
            "billing.subscription.usage_recorded.v1", "dispute.evidence_submitted.v1",
            "dispute.opened.v1", "dispute.resolved.v1",
            "payment.attempt.invalid_provider_result.v1", "payment.attempt.resolved.v1",
            "payment.authorization.closed.v1", "payment.authorized.v1",
            "payment.canceled.v1", "payment.capture.resolved.v1", "payment.captured.v1",
            "payment.failed.v1", "payment.intent.canceled.v1",
            "payment.intent.created.v1", "payment.partially_captured.v1",
            "payment.query.invalid_provider_result.v1", "payment.query.recovered.v1",
            "payment.query.resolved.v1", "payment.void.resolved.v1",
            "refund.approved.v1", "refund.failed.v1", "refund.processing.v1",
            "refund.provider_canceled.v1", "refund.provider_failed.v1",
            "refund.provider_processing.v1", "refund.provider_succeeded.v1",
            "refund.recovery.requested.v1", "refund.request.denied.v1",
            "refund.requested.v1", "refund.succeeded.v1", "refund.unknown.v1",
            "risk.admin_operation.applied.v1", "rollout.approval_recorded.v1");
    private static final Set<String> CAPTURE_FIELDS = Set.of(
            "aggregate_revision", "amount_minor", "business_order_digest", "captured_at",
            "currency", "payment_intent_id", "project_id", "provider");
    private static final Set<String> REFUND_FIELDS = Set.of(
            "aggregate_revision", "amount_minor", "currency", "payment_intent_id",
            "project_id", "provider", "provider_refund_id", "refund_id", "refunded_at");

    public record FinancialFact(String eventName, String sourceKind, long amountMinor,
            String currency, String provider, Instant effectiveAt) {
        public FinancialFact {
            if (!FINANCIAL_EVENTS.contains(eventName) || sourceKind == null
                    || sourceKind.isBlank() || amountMinor <= 0 || currency == null
                    || !currency.matches("[A-Z]{3}") || provider == null
                    || !provider.matches("[a-z][a-z0-9_]{1,31}")) {
                throw new IllegalArgumentException("invalid financial event fact");
            }
            Objects.requireNonNull(effectiveAt, "effectiveAt");
        }

        static FinancialFact from(JdbcEventDeliveryStore.InboxMessage message) {
            if (!FINANCIAL_EVENTS.contains(message.eventName())) {
                throw new MissingPostingPolicyException(
                        "no governed ledger policy exists for event " + message.eventName());
            }
            Map<String, Object> payload = message.envelope().payload();
            Set<String> expectedFields = "payment_intent.captured".equals(message.eventName())
                    ? CAPTURE_FIELDS : REFUND_FIELDS;
            if (!payload.keySet().equals(expectedFields)) {
                throw new IllegalArgumentException(
                        "financial payload has missing or unknown catalog fields");
            }
            requireUuid(payload, "project_id", message.projectId());
            requireLong(payload, "aggregate_revision", message.aggregateRevision());
            String sourceKind;
            String semanticTimestamp;
            if ("payment_intent.captured".equals(message.eventName())) {
                requireUuid(payload, "payment_intent_id", message.aggregateId());
                requireSha256(payload, "business_order_digest");
                sourceKind = "payment";
                semanticTimestamp = "captured_at";
            } else {
                requireUuid(payload, "refund_id", message.aggregateId());
                uuid(payload, "payment_intent_id");
                boundedText(payload, "provider_refund_id", 160);
                sourceKind = "refund";
                semanticTimestamp = "refunded_at";
            }
            Instant effectiveAt = instant(payload, semanticTimestamp);
            if (!effectiveAt.equals(message.occurredAt())) {
                throw new IllegalArgumentException(
                        "semantic timestamp does not match envelope occurred_at");
            }
            return new FinancialFact(message.eventName(), sourceKind,
                    positiveLong(payload, "amount_minor"), text(payload, "currency"),
                    text(payload, "provider"), effectiveAt);
        }
    }

    public record PostingPolicy(long version, String sourceKind, String description,
            String debitAccountId, String creditAccountId) {
        public PostingPolicy {
            if (version < 1 || sourceKind == null || sourceKind.isBlank()
                    || description == null || description.isBlank()) {
                throw new IllegalArgumentException("invalid ledger posting policy");
            }
            UUID.fromString(debitAccountId);
            UUID.fromString(creditAccountId);
            if (debitAccountId.equals(creditAccountId)) {
                throw new IllegalArgumentException("debit and credit accounts must differ");
            }
        }
    }

    @FunctionalInterface
    public interface PostingPolicyResolver {
        PostingPolicy resolve(Connection connection,
                JdbcEventDeliveryStore.InboxMessage message, FinancialFact fact)
                throws SQLException;
    }

    private enum RevisionDecision {
        APPLY,
        DUPLICATE
    }

    private final JdbcEventDeliveryStore delivery;
    private final LedgerService ledger;
    private final PostingPolicyResolver policies;
    private final Duration leaseTtl;
    private final Duration retryDelay;

    public LedgerPostingConsumer(JdbcEventDeliveryStore delivery, LedgerService ledger,
            PostingPolicyResolver policies, Duration leaseTtl, Duration retryDelay) {
        this.delivery = Objects.requireNonNull(delivery, "delivery");
        this.ledger = Objects.requireNonNull(ledger, "ledger");
        this.policies = Objects.requireNonNull(policies, "policies");
        this.leaseTtl = positive(leaseTtl, "leaseTtl");
        this.retryDelay = positive(retryDelay, "retryDelay");
    }

    public JdbcEventDeliveryStore.InboxOutcome consume(
            JdbcEventDeliveryStore.InboxMessage message, String workerId, Instant now) {
        Objects.requireNonNull(message, "message");
        // Legacy dotted-version events remain publishable for compatibility but never post money.
        boolean legacyInternal = LEGACY_INTERNAL_EVENTS.contains(message.eventName());
        FinancialFact fact = legacyInternal ? null : FinancialFact.from(message);
        return delivery.consume(CONSUMER_NAME, message, workerId, now, leaseTtl, retryDelay,
                (connection, verified) -> apply(connection, verified, fact, legacyInternal, now));
    }

    private JdbcEventDeliveryStore.InboxOutcome apply(Connection connection,
            JdbcEventDeliveryStore.InboxMessage message, FinancialFact fact,
            boolean legacyInternal, Instant now) throws SQLException {
        String digest = JdbcEventDeliveryStore.sha256(message.envelope().canonicalJson());
        RevisionDecision revision = revisionDecision(connection, message, digest);
        if (revision == RevisionDecision.DUPLICATE) {
            return JdbcEventDeliveryStore.InboxOutcome.DUPLICATE;
        }
        if (legacyInternal) {
            advanceRevision(connection, message, digest, now);
            return JdbcEventDeliveryStore.InboxOutcome.APPLIED;
        }
        PostingPolicy policy = policies.resolve(connection, message, fact);
        if (!policy.sourceKind().equals(fact.sourceKind())) {
            throw new MissingPostingPolicyException(
                    "posting policy source kind does not match the catalog event");
        }
        ledger.post(connection, new LedgerService.PostRequest(message.tenantId().toString(),
                fact.sourceKind(), sourceId(message), fact.effectiveAt(),
                policy.description() + " [policy-v" + policy.version() + "]",
                java.util.List.of(
                        new LedgerService.EntryDraft(policy.debitAccountId(),
                                LedgerService.Direction.DEBIT, fact.amountMinor(), fact.currency()),
                        new LedgerService.EntryDraft(policy.creditAccountId(),
                                LedgerService.Direction.CREDIT, fact.amountMinor(), fact.currency()))));
        advanceRevision(connection, message, digest, now);
        return JdbcEventDeliveryStore.InboxOutcome.APPLIED;
    }

    private static RevisionDecision revisionDecision(Connection connection,
            JdbcEventDeliveryStore.InboxMessage message, String digest) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT last_revision, last_event_id, last_envelope_sha256
                  FROM ledger_event_revision_guard
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid
                   AND aggregate_type = ? AND aggregate_id = ?::uuid
                 FOR UPDATE
                """)) {
            statement.setString(1, message.tenantId().toString());
            statement.setString(2, message.projectId().toString());
            statement.setString(3, message.aggregateType());
            statement.setString(4, message.aggregateId().toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    if (message.aggregateRevision() != 1) {
                        throw new OutOfOrderFinancialEventException(
                                "first observed aggregate revision is not one");
                    }
                    return RevisionDecision.APPLY;
                }
                long previous = result.getLong("last_revision");
                if (message.aggregateRevision() == previous
                        && message.eventId().equals(result.getObject("last_event_id", UUID.class))
                        && digest.equals(result.getString("last_envelope_sha256"))) {
                    return RevisionDecision.DUPLICATE;
                }
                if (message.aggregateRevision() != previous + 1) {
                    throw new OutOfOrderFinancialEventException(
                            "aggregate revision is duplicated, stale or has a gap");
                }
                return RevisionDecision.APPLY;
            }
        }
    }

    private static void advanceRevision(Connection connection,
            JdbcEventDeliveryStore.InboxMessage message, String digest, Instant now)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO ledger_event_revision_guard
                  (tenant_id, project_id, aggregate_type, aggregate_id, last_revision,
                   last_event_id, last_event_name, last_envelope_sha256, updated_at)
                VALUES (?::uuid, ?::uuid, ?, ?::uuid, ?, ?::uuid, ?, ?, ?::timestamptz)
                ON CONFLICT (tenant_id, project_id, aggregate_type, aggregate_id) DO UPDATE
                   SET last_revision = EXCLUDED.last_revision,
                       last_event_id = EXCLUDED.last_event_id,
                       last_event_name = EXCLUDED.last_event_name,
                       last_envelope_sha256 = EXCLUDED.last_envelope_sha256,
                       updated_at = EXCLUDED.updated_at
                 WHERE ledger_event_revision_guard.last_revision + 1 = EXCLUDED.last_revision
                """)) {
            statement.setString(1, message.tenantId().toString());
            statement.setString(2, message.projectId().toString());
            statement.setString(3, message.aggregateType());
            statement.setString(4, message.aggregateId().toString());
            statement.setLong(5, message.aggregateRevision());
            statement.setString(6, message.eventId().toString());
            statement.setString(7, message.eventName());
            statement.setString(8, digest);
            statement.setString(9, now.toString());
            if (statement.executeUpdate() != 1) {
                throw new OutOfOrderFinancialEventException(
                        "aggregate revision fence changed during posting");
            }
        }
    }

    private static String sourceId(JdbcEventDeliveryStore.InboxMessage message) {
        return message.eventName() + ":" + message.aggregateId() + ":"
                + message.aggregateRevision();
    }

    private static String text(Map<String, Object> payload, String field) {
        Object value = payload.get(field);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return text;
    }

    private static long positiveLong(Map<String, Object> payload, String field) {
        Object value = payload.get(field);
        if (!(value instanceof Long number) || number <= 0) {
            throw new IllegalArgumentException(field + " must be a positive integer");
        }
        return number;
    }

    private static void requireLong(Map<String, Object> payload, String field, long expected) {
        if (positiveLong(payload, field) != expected) {
            throw new SecurityException(field + " does not match the verified envelope");
        }
    }

    private static void requireUuid(Map<String, Object> payload, String field, UUID expected) {
        UUID actual = uuid(payload, field);
        if (!actual.equals(expected)) {
            throw new SecurityException(field + " does not match the verified envelope");
        }
    }

    private static UUID uuid(Map<String, Object> payload, String field) {
        try {
            return UUID.fromString(text(payload, field));
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException(field + " must be a UUID", failure);
        }
    }

    private static void requireSha256(Map<String, Object> payload, String field) {
        if (!text(payload, field).matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be a lowercase SHA-256 digest");
        }
    }

    private static String boundedText(Map<String, Object> payload, String field, int maximum) {
        String value = text(payload, field);
        if (value.length() > maximum) {
            throw new IllegalArgumentException(field + " exceeds its catalog bound");
        }
        return value;
    }

    private static Instant instant(Map<String, Object> payload, String field) {
        try {
            return Instant.parse(text(payload, field));
        } catch (DateTimeParseException failure) {
            throw new IllegalArgumentException(field + " must be an RFC3339 instant", failure);
        }
    }

    private static Duration positive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }

    public static final class MissingPostingPolicyException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public MissingPostingPolicyException(String message) {
            super(message);
        }
    }

    public static final class OutOfOrderFinancialEventException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public OutOfOrderFinancialEventException(String message) {
            super(message);
        }
    }
}
