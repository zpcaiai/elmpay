package com.elmpay.webhook.ingress;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/** PostgreSQL lease/fencing implementation for verified provider webhook effects. */
final class JdbcWebhookInboxStore implements WebhookInboxStore {
    static final String TERMINALIZE_EXHAUSTED_SQL = """
            UPDATE provider_webhook_inbox
               SET processing_status = 'FAILED',
                   next_attempt_at = NULL,
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   terminal_failure = TRUE,
                   last_error_code = 'MAX_ATTEMPTS_EXHAUSTED',
                   diagnostic_summary = 'failure=MAX_ATTEMPTS_EXHAUSTED;verification='
                       || substring(verification_digest FROM 1 FOR 16)
                       || ';attempt=' || processing_attempts
             WHERE tenant_id = ?
               AND terminal_failure = FALSE
               AND processing_attempts >= ?
               AND (
                   processing_status IN ('VERIFIED', 'FAILED')
                   OR (processing_status = 'PROCESSING'
                       AND lease_expires_at <= ?::timestamptz)
               )
            """;

    static final String CLAIM_SQL = """
            WITH candidate AS (
                SELECT inbox_id
                  FROM provider_webhook_inbox
                 WHERE tenant_id = ?
                   AND terminal_failure = FALSE
                   AND processing_attempts < ?
                   AND canonical_payload_sha256 IS NOT NULL
                   AND verification_digest IS NOT NULL
                   AND (
                       (processing_status IN ('VERIFIED', 'FAILED')
                        AND COALESCE(next_attempt_at, received_at) <= ?::timestamptz)
                       OR
                       (processing_status = 'PROCESSING'
                        AND lease_expires_at <= ?::timestamptz)
                   )
                 ORDER BY COALESCE(next_attempt_at, received_at), inbox_id
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
            )
            UPDATE provider_webhook_inbox inbox
               SET processing_status = 'PROCESSING',
                   processing_attempts = inbox.processing_attempts + 1,
                   last_attempt_at = ?::timestamptz,
                   next_attempt_at = NULL,
                   lease_owner = ?,
                   lease_expires_at = ?::timestamptz,
                   fencing_token = inbox.fencing_token + 1,
                   last_error_code = NULL,
                   diagnostic_summary = NULL
              FROM candidate
             WHERE inbox.tenant_id = ?
               AND inbox.inbox_id = candidate.inbox_id
            RETURNING inbox.inbox_id, inbox.tenant_id, inbox.project_id, inbox.provider,
                      inbox.merchant_account_id, inbox.provider_event_id, inbox.event_type,
                      inbox.provider_payment_id, inbox.business_order_no, inbox.occurred_at,
                      inbox.received_at, inbox.signature_key_id, inbox.amount_minor,
                      inbox.currency, inbox.canonical_schema, inbox.raw_body_sha256,
                      inbox.canonical_payload_sha256, inbox.verification_digest,
                      inbox.canonical_payload, inbox.processing_attempts, inbox.fencing_token,
                      inbox.lease_expires_at
            """;

    static final String LOCK_CLAIM_SQL = """
            SELECT tenant_id, project_id, provider, merchant_account_id, provider_event_id,
                   event_type, provider_payment_id, business_order_no, occurred_at, received_at,
                   signature_key_id, amount_minor, currency, canonical_schema, raw_body_sha256,
                   canonical_payload_sha256,
                   verification_digest, canonical_payload, processing_status, processing_attempts,
                   lease_owner, lease_expires_at, fencing_token
              FROM provider_webhook_inbox
             WHERE tenant_id = ? AND inbox_id = ?
             FOR UPDATE
            """;

    static final String INSERT_EFFECT_COMMIT_SQL = """
            INSERT INTO provider_webhook_effect_commit
              (tenant_id, inbox_id, verification_digest, fencing_token, committed_at)
            VALUES (?, ?, ?, ?, ?::timestamptz)
            ON CONFLICT (tenant_id, inbox_id) DO NOTHING
            """;

    static final String SELECT_EFFECT_COMMIT_SQL = """
            SELECT verification_digest
              FROM provider_webhook_effect_commit
             WHERE tenant_id = ? AND inbox_id = ?
            """;

    static final String MARK_PROCESSED_SQL = """
            UPDATE provider_webhook_inbox
               SET processing_status = 'PROCESSED',
                   processed_at = ?::timestamptz,
                   next_attempt_at = NULL,
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   terminal_failure = FALSE,
                   last_error_code = NULL,
                   diagnostic_summary = NULL
             WHERE tenant_id = ? AND inbox_id = ?
               AND processing_status = 'PROCESSING'
               AND lease_owner = ? AND fencing_token = ?
               AND lease_expires_at > ?::timestamptz
               AND verification_digest = ?
            """;

    static final String RECORD_FAILURE_SQL = """
            UPDATE provider_webhook_inbox
               SET processing_status = 'FAILED',
                   next_attempt_at = CASE WHEN ? THEN NULL ELSE ?::timestamptz END,
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   terminal_failure = ?,
                   last_error_code = ?,
                   diagnostic_summary = ?
             WHERE tenant_id = ? AND inbox_id = ?
               AND processing_status = 'PROCESSING'
               AND lease_owner = ? AND fencing_token = ?
               AND lease_expires_at > ?::timestamptz
               AND verification_digest = ?
            """;

    private final DataSource dataSource;

    JdbcWebhookInboxStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public int terminalizeExhausted(String tenantId, Instant now, int maxAttempts) {
        return transaction(tenantId, "cannot terminalize exhausted provider webhook",
                connection -> {
                    try (PreparedStatement statement = connection.prepareStatement(
                            TERMINALIZE_EXHAUSTED_SQL)) {
                        statement.setString(1, tenantId);
                        statement.setInt(2, maxAttempts);
                        statement.setString(3, now.toString());
                        return statement.executeUpdate();
                    }
                });
    }

    @Override
    public Optional<Claim> claim(String tenantId, String workerId, Instant now, Duration leaseTtl,
            int maxAttempts) {
        return transaction(tenantId, "cannot claim verified provider webhook", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(CLAIM_SQL)) {
                statement.setString(1, tenantId);
                statement.setInt(2, maxAttempts);
                statement.setString(3, now.toString());
                statement.setString(4, now.toString());
                statement.setString(5, now.toString());
                statement.setString(6, workerId);
                statement.setString(7, now.plus(leaseTtl).toString());
                statement.setString(8, tenantId);
                try (ResultSet row = statement.executeQuery()) {
                    if (!row.next()) {
                        return Optional.empty();
                    }
                    WebhookEffectPort.Effect effect = effect(row);
                    return Optional.of(new Claim(effect, workerId,
                            requiredInstant(row, "lease_expires_at")));
                }
            }
        });
    }

    @Override
    public ApplyOutcome apply(Claim claim, Instant now, WebhookEffectPort effectPort) {
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(effectPort, "effectPort");
        WebhookEffectPort.Effect expected = claim.effect();
        return transaction(expected.tenantId(), "cannot apply verified provider webhook",
                connection -> {
                    lockAndValidate(connection, claim, now);
                    boolean inserted = insertEffectCommit(connection, expected, now);
                    if (inserted) {
                        try {
                            effectPort.apply(connection, expected);
                        } catch (Exception failure) {
                            if (failure instanceof InterruptedException) {
                                Thread.currentThread().interrupt();
                            }
                            if (failure instanceof WebhookEffectPort.EffectFailure classified) {
                                throw new DispatchException(classified.failureCode(),
                                        classified.permanent(), classified);
                            }
                            throw new DispatchException(safeFailureCode(failure), false, failure);
                        }
                    } else {
                        requireMatchingEffectCommit(connection, expected);
                    }
                    markProcessed(connection, claim, now);
                    return inserted ? ApplyOutcome.PROCESSED : ApplyOutcome.DUPLICATE_EFFECT;
                });
    }

    @Override
    public boolean recordFailure(Claim claim, Instant failedAt, Instant nextAttemptAt,
            boolean terminal, String failureCode, String diagnosticSummary) {
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(failedAt, "failedAt");
        Objects.requireNonNull(nextAttemptAt, "nextAttemptAt");
        requireSafe(failureCode, "failureCode", 80);
        requireSafe(diagnosticSummary, "diagnosticSummary", 512);
        WebhookEffectPort.Effect effect = claim.effect();
        return transaction(effect.tenantId(), "cannot reschedule verified provider webhook",
                connection -> {
                    try (PreparedStatement statement = connection.prepareStatement(
                            RECORD_FAILURE_SQL)) {
                        statement.setBoolean(1, terminal);
                        statement.setString(2, nextAttemptAt.toString());
                        statement.setBoolean(3, terminal);
                        statement.setString(4, failureCode);
                        statement.setString(5, diagnosticSummary);
                        statement.setString(6, effect.tenantId());
                        statement.setLong(7, effect.inboxId());
                        statement.setString(8, claim.workerId());
                        statement.setLong(9, effect.fencingToken());
                        statement.setString(10, failedAt.toString());
                        statement.setString(11, effect.verificationDigest());
                        return statement.executeUpdate() == 1;
                    }
                });
    }

    private static void lockAndValidate(Connection connection, Claim claim, Instant now)
            throws SQLException {
        WebhookEffectPort.Effect expected = claim.effect();
        try (PreparedStatement statement = connection.prepareStatement(LOCK_CLAIM_SQL)) {
            statement.setString(1, expected.tenantId());
            statement.setLong(2, expected.inboxId());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()
                        || !"PROCESSING".equals(row.getString("processing_status"))
                        || !claim.workerId().equals(row.getString("lease_owner"))
                        || expected.fencingToken() != row.getLong("fencing_token")
                        || expected.processingAttempt() != row.getInt("processing_attempts")) {
                    throw new LeaseLostException("webhook lease is superseded");
                }
                Timestamp lease = row.getTimestamp("lease_expires_at");
                if (lease == null || !lease.toInstant().isAfter(now)) {
                    throw new LeaseLostException("webhook lease is expired");
                }
                WebhookEffectPort.Effect persisted = effect(row, expected.inboxId());
                if (!sameImmutableFacts(expected, persisted)) {
                    throw new IdentityConflictException(
                            "verified webhook facts changed after lease claim");
                }
                validatePersistedDigests(persisted);
            }
        }
    }

    private static boolean insertEffectCommit(Connection connection,
            WebhookEffectPort.Effect effect, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT_EFFECT_COMMIT_SQL)) {
            statement.setString(1, effect.tenantId());
            statement.setLong(2, effect.inboxId());
            statement.setString(3, effect.verificationDigest());
            statement.setLong(4, effect.fencingToken());
            statement.setString(5, now.toString());
            return statement.executeUpdate() == 1;
        }
    }

    private static void requireMatchingEffectCommit(Connection connection,
            WebhookEffectPort.Effect effect) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT_EFFECT_COMMIT_SQL)) {
            statement.setString(1, effect.tenantId());
            statement.setLong(2, effect.inboxId());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()
                        || !effect.verificationDigest().equals(
                                row.getString("verification_digest"))) {
                    throw new IdentityConflictException(
                            "effect commit conflicts with immutable verification digest");
                }
            }
        }
    }

    private static void markProcessed(Connection connection, Claim claim, Instant now)
            throws SQLException {
        WebhookEffectPort.Effect effect = claim.effect();
        try (PreparedStatement statement = connection.prepareStatement(MARK_PROCESSED_SQL)) {
            statement.setString(1, now.toString());
            statement.setString(2, effect.tenantId());
            statement.setLong(3, effect.inboxId());
            statement.setString(4, claim.workerId());
            statement.setLong(5, effect.fencingToken());
            statement.setString(6, now.toString());
            statement.setString(7, effect.verificationDigest());
            if (statement.executeUpdate() != 1) {
                throw new LeaseLostException("stale fence cannot mark webhook processed");
            }
        }
    }

    private static WebhookEffectPort.Effect effect(ResultSet row) throws SQLException {
        return effect(row, row.getLong("inbox_id"));
    }

    private static WebhookEffectPort.Effect effect(ResultSet row, long inboxId)
            throws SQLException {
        return new WebhookEffectPort.Effect(inboxId, row.getString("tenant_id"),
                row.getString("project_id"), row.getString("provider"),
                row.getString("merchant_account_id"), row.getString("provider_event_id"),
                row.getString("event_type"), row.getString("provider_payment_id"),
                row.getString("business_order_no"), requiredInstant(row, "occurred_at"),
                requiredInstant(row, "received_at"), row.getString("signature_key_id"),
                nullableLong(row, "amount_minor"), row.getString("currency"),
                row.getString("canonical_schema"), row.getString("raw_body_sha256"),
                row.getString("canonical_payload_sha256"),
                row.getString("verification_digest"), row.getBytes("canonical_payload"),
                row.getInt("processing_attempts"), row.getLong("fencing_token"));
    }

    private static Instant requiredInstant(ResultSet row, String column) throws SQLException {
        Timestamp value = row.getTimestamp(column);
        if (value == null) {
            throw new IdentityConflictException(column + " is missing");
        }
        return value.toInstant();
    }

    private static Long nullableLong(ResultSet row, String column) throws SQLException {
        long value = row.getLong(column);
        return row.wasNull() ? null : value;
    }

    private static boolean sameImmutableFacts(WebhookEffectPort.Effect left,
            WebhookEffectPort.Effect right) {
        return left.inboxId() == right.inboxId()
                && left.tenantId().equals(right.tenantId())
                && left.projectId().equals(right.projectId())
                && left.provider().equals(right.provider())
                && left.merchantAccountId().equals(right.merchantAccountId())
                && left.providerEventId().equals(right.providerEventId())
                && left.eventType().equals(right.eventType())
                && left.providerPaymentId().equals(right.providerPaymentId())
                && left.businessOrderNo().equals(right.businessOrderNo())
                && left.occurredAt().equals(right.occurredAt())
                && left.receivedAt().equals(right.receivedAt())
                && left.signatureKeyId().equals(right.signatureKeyId())
                && Objects.equals(left.amountMinor(), right.amountMinor())
                && Objects.equals(left.currency(), right.currency())
                && left.canonicalSchema().equals(right.canonicalSchema())
                && left.rawBodySha256().equals(right.rawBodySha256())
                && left.canonicalPayloadSha256().equals(right.canonicalPayloadSha256())
                && left.verificationDigest().equals(right.verificationDigest())
                && java.util.Arrays.equals(left.canonicalPayload(), right.canonicalPayload())
                && left.processingAttempt() == right.processingAttempt()
                && left.fencingToken() == right.fencingToken();
    }

    private static void validatePersistedDigests(WebhookEffectPort.Effect effect) {
        String canonicalDigest = WebhookVerificationDigests.sha256(effect.canonicalPayload());
        if (!canonicalDigest.equals(effect.canonicalPayloadSha256())) {
            throw new IdentityConflictException("canonical webhook digest does not match payload");
        }
        WebhookIngressService.Context context = new WebhookIngressService.Context(
                effect.tenantId(), effect.projectId(), effect.provider(),
                effect.merchantAccountId(), effect.receivedAt());
        WebhookIngressService.VerifiedEvent event = new WebhookIngressService.VerifiedEvent(
                effect.providerEventId(), effect.eventType(), effect.providerPaymentId(),
                effect.businessOrderNo(), effect.occurredAt(), effect.signatureKeyId(),
                effect.amountMinor(), effect.currency(), effect.canonicalSchema(),
                effect.canonicalPayload());
        String verificationDigest = WebhookVerificationDigests.verificationDigest(context, event,
                effect.rawBodySha256(), effect.canonicalPayloadSha256());
        if (!verificationDigest.equals(effect.verificationDigest())) {
            throw new IdentityConflictException("webhook verification digest is invalid");
        }
    }

    private static String safeFailureCode(Exception failure) {
        String type = failure.getClass().getSimpleName();
        return type.matches("[A-Za-z0-9_.-]{1,80}") ? type : "WebhookEffectFailure";
    }

    private static void requireSafe(String value, String field, int maximum) {
        if (value == null || !value.matches("[A-Za-z0-9_.:;=-]{1," + maximum + "}")) {
            throw new IllegalArgumentException(field + " contains unsafe characters");
        }
    }

    private static void setTenant(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId);
            statement.execute();
        }
    }

    private <T> T transaction(String tenantId, String failureMessage, SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                T result = work.execute(connection);
                connection.commit();
                return result;
            } catch (Exception failure) {
                rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new StoreException(failureMessage, failure);
            }
        } catch (SQLException failure) {
            throw new StoreException(failureMessage, failure);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T execute(Connection connection) throws Exception;
    }
}
