package com.elmpay.scheduler.events;

import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL outbox relay and consumer inbox with leases and monotonic fencing tokens. */
public final class JdbcEventDeliveryStore implements OutboxRelay.Store {
    static final String CLAIM_OUTBOX_SQL = """
            SELECT sequence_no, id, tenant_id, project_id, aggregate_type, aggregate_id,
                   event_type, event_version, payload::text AS payload_json, correlation_id,
                   created_at, delivery_attempts, fencing_token
              FROM outbox_event
             WHERE tenant_id = ?::uuid AND published_at IS NULL
               AND next_attempt_at <= ?::timestamptz
               AND (lease_until IS NULL OR lease_until <= ?::timestamptz)
             ORDER BY sequence_no
             FOR UPDATE SKIP LOCKED
             LIMIT 1
            """;
    static final String CLAIM_OUTBOX_UPDATE_SQL = """
            UPDATE outbox_event
               SET lease_owner = ?, lease_until = ?::timestamptz,
                   fencing_token = fencing_token + 1,
                   delivery_attempts = delivery_attempts + 1,
                   last_error_code = NULL
             WHERE tenant_id = ?::uuid AND sequence_no = ? AND fencing_token = ?
            RETURNING fencing_token, delivery_attempts
            """;
    static final String MARK_PUBLISHED_SQL = """
            UPDATE outbox_event
               SET published_at = ?::timestamptz, lease_owner = NULL, lease_until = NULL,
                   next_attempt_at = ?::timestamptz, last_error_code = NULL
             WHERE tenant_id = ?::uuid AND sequence_no = ? AND published_at IS NULL
               AND lease_owner = ? AND fencing_token = ?
               AND lease_until > ?::timestamptz
            """;
    static final String RECORD_FAILURE_SQL = """
            UPDATE outbox_event
               SET lease_owner = NULL, lease_until = NULL,
                   next_attempt_at = ?::timestamptz, last_error_code = ?
             WHERE tenant_id = ?::uuid AND sequence_no = ? AND published_at IS NULL
               AND lease_owner = ? AND fencing_token = ?
               AND lease_until > ?::timestamptz
            """;
    static final String INBOX_SELECT_SQL = """
            SELECT payload_sha256, state, lease_owner, lease_until, fencing_token,
                   delivery_attempts, next_attempt_at
              FROM consumer_event_inbox
             WHERE tenant_id = ?::uuid AND consumer_name = ? AND source_event_id = ?::uuid
             FOR UPDATE
            """;
    static final String INBOX_PROCESS_SELECT_SQL = INBOX_SELECT_SQL;

    public enum InboxOutcome {
        APPLIED,
        DUPLICATE,
        BUSY
    }

    public record InboxMessage(UUID eventId, UUID tenantId, UUID projectId, String eventType,
            int eventVersion, String payloadJson, String correlationId, Instant occurredAt) {
        public InboxMessage {
            Objects.requireNonNull(eventId, "eventId");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            OutboxRelay.requireText(eventType, "eventType");
            OutboxRelay.requireText(payloadJson, "payloadJson");
            OutboxRelay.requireText(correlationId, "correlationId");
            Objects.requireNonNull(occurredAt, "occurredAt");
            if (eventVersion <= 0) {
                throw new IllegalArgumentException("eventVersion must be positive");
            }
        }

        public static InboxMessage from(OutboxRelay.Message message) {
            Objects.requireNonNull(message, "message");
            return new InboxMessage(message.eventId(), message.tenantId(), message.projectId(),
                    message.eventType(), message.eventVersion(), message.payloadJson(),
                    message.correlationId(), message.createdAt());
        }
    }

    /** Business writes use this same transaction as the durable processed marker. */
    @FunctionalInterface
    public interface TransactionalConsumer {
        void handle(Connection connection, InboxMessage message) throws Exception;
    }

    private record InboxLease(InboxOutcome outcome, String consumerName, String workerId,
            long fencingToken, String payloadDigest) {
    }

    private final DataSource dataSource;

    public JdbcEventDeliveryStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<OutboxRelay.Message> claim(UUID tenantId, String workerId, Instant now,
            Duration leaseTtl) {
        Objects.requireNonNull(tenantId, "tenantId");
        OutboxRelay.requireText(workerId, "workerId");
        Objects.requireNonNull(now, "now");
        requirePositive(leaseTtl, "leaseTtl");
        return transaction(tenantId, "cannot claim outbox event", connection -> {
            try (PreparedStatement select = connection.prepareStatement(CLAIM_OUTBOX_SQL)) {
                select.setString(1, tenantId.toString());
                select.setString(2, now.toString());
                select.setString(3, now.toString());
                try (ResultSet result = select.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }
                    long sequence = result.getLong("sequence_no");
                    long previousFence = result.getLong("fencing_token");
                    try (PreparedStatement update = connection.prepareStatement(
                            CLAIM_OUTBOX_UPDATE_SQL)) {
                        update.setString(1, workerId);
                        update.setString(2, now.plus(leaseTtl).toString());
                        update.setString(3, tenantId.toString());
                        update.setLong(4, sequence);
                        update.setLong(5, previousFence);
                        try (ResultSet claimed = update.executeQuery()) {
                            if (!claimed.next()) {
                                throw new OutboxRelay.LeaseLostException(
                                        "outbox claim lost its fencing compare-and-set");
                            }
                            return Optional.of(new OutboxRelay.Message(sequence,
                                    result.getObject("id", UUID.class),
                                    result.getObject("tenant_id", UUID.class),
                                    result.getObject("project_id", UUID.class),
                                    result.getString("aggregate_type"),
                                    result.getObject("aggregate_id", UUID.class),
                                    result.getString("event_type"), result.getInt("event_version"),
                                    result.getString("payload_json"),
                                    result.getString("correlation_id"),
                                    result.getTimestamp("created_at").toInstant(),
                                    claimed.getInt("delivery_attempts"), workerId,
                                    claimed.getLong("fencing_token")));
                        }
                    }
                }
            }
        });
    }

    @Override
    public void markPublished(OutboxRelay.Message message, Instant acknowledgedAt) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(acknowledgedAt, "acknowledgedAt");
        transaction(message.tenantId(), "cannot mark outbox event published", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(MARK_PUBLISHED_SQL)) {
                statement.setString(1, acknowledgedAt.toString());
                statement.setString(2, acknowledgedAt.toString());
                statement.setString(3, message.tenantId().toString());
                statement.setLong(4, message.sequenceNo());
                statement.setString(5, message.leaseOwner());
                statement.setLong(6, message.fencingToken());
                statement.setString(7, acknowledgedAt.toString());
                requireUpdated(statement.executeUpdate(), "stale fencing token cannot acknowledge");
            }
            return null;
        });
    }

    @Override
    public void recordFailure(OutboxRelay.Message message, Instant failedAt, Duration retryDelay,
            String failureCode) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(failedAt, "failedAt");
        requirePositive(retryDelay, "retryDelay");
        String safeCode = safeFailureCode(failureCode);
        transaction(message.tenantId(), "cannot reschedule outbox event", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(RECORD_FAILURE_SQL)) {
                statement.setString(1, failedAt.plus(retryDelay).toString());
                statement.setString(2, safeCode);
                statement.setString(3, message.tenantId().toString());
                statement.setLong(4, message.sequenceNo());
                statement.setString(5, message.leaseOwner());
                statement.setLong(6, message.fencingToken());
                statement.setString(7, failedAt.toString());
                requireUpdated(statement.executeUpdate(), "stale fencing token cannot reschedule");
            }
            return null;
        });
    }

    /**
     * Applies one incoming event exactly once with respect to database business effects.
     *
     * <p>The durable lease is committed first. The handler then runs in the same transaction as
     * the processed marker, so a crash rolls both back; another worker may retry after lease
     * expiry. External side effects must themselves use an outbox in this supplied connection.
     */
    public InboxOutcome consume(String consumerName, InboxMessage message, String workerId,
            Instant now, Duration leaseTtl, Duration retryDelay,
            TransactionalConsumer consumer) {
        OutboxRelay.requireText(consumerName, "consumerName");
        Objects.requireNonNull(message, "message");
        OutboxRelay.requireText(workerId, "workerId");
        Objects.requireNonNull(now, "now");
        requirePositive(leaseTtl, "leaseTtl");
        requirePositive(retryDelay, "retryDelay");
        Objects.requireNonNull(consumer, "consumer");
        String digest = sha256(message.payloadJson());
        InboxLease lease = claimInbox(consumerName, message, workerId, now, leaseTtl, digest);
        if (lease.outcome() != InboxOutcome.APPLIED) {
            return lease.outcome();
        }
        try {
            applyInbox(lease, message, now, consumer);
            return InboxOutcome.APPLIED;
        } catch (RuntimeException failure) {
            try {
                recordInboxFailure(lease, message, now, retryDelay,
                        failure.getClass().getSimpleName());
            } catch (RuntimeException rescheduleFailure) {
                failure.addSuppressed(rescheduleFailure);
            }
            throw failure;
        }
    }

    private InboxLease claimInbox(String consumerName, InboxMessage message, String workerId,
            Instant now, Duration leaseTtl, String digest) {
        return transaction(message.tenantId(), "cannot claim consumer inbox event", connection -> {
            boolean inserted;
            try (PreparedStatement insert = connection.prepareStatement("""
                    INSERT INTO consumer_event_inbox
                      (tenant_id, consumer_name, source_event_id, project_id, payload_sha256,
                       state, lease_owner, lease_until, fencing_token, delivery_attempts,
                       next_attempt_at, received_at)
                    VALUES (?::uuid, ?, ?::uuid, ?::uuid, ?, 'processing', ?, ?::timestamptz,
                            1, 1, ?::timestamptz, ?::timestamptz)
                    ON CONFLICT (tenant_id, consumer_name, source_event_id) DO NOTHING
                    """)) {
                insert.setString(1, message.tenantId().toString());
                insert.setString(2, consumerName);
                insert.setString(3, message.eventId().toString());
                insert.setString(4, message.projectId().toString());
                insert.setString(5, digest);
                insert.setString(6, workerId);
                insert.setString(7, now.plus(leaseTtl).toString());
                insert.setString(8, now.toString());
                insert.setString(9, now.toString());
                inserted = insert.executeUpdate() == 1;
            }
            try (PreparedStatement select = connection.prepareStatement(INBOX_SELECT_SQL)) {
                bindInboxKey(select, message, consumerName);
                try (ResultSet row = select.executeQuery()) {
                    if (!row.next()) {
                        throw new EventStoreException("inbox row disappeared after insert");
                    }
                    if (!digest.equals(row.getString("payload_sha256"))) {
                        throw new EventIdentityConflictException(
                                "source event id was reused with a different payload digest");
                    }
                    if (inserted) {
                        return new InboxLease(InboxOutcome.APPLIED, consumerName, workerId, 1, digest);
                    }
                    if ("processed".equals(row.getString("state"))) {
                        return new InboxLease(InboxOutcome.DUPLICATE, consumerName, workerId,
                                row.getLong("fencing_token"), digest);
                    }
                    Timestamp leaseUntil = row.getTimestamp("lease_until");
                    Timestamp nextAttempt = row.getTimestamp("next_attempt_at");
                    if ((leaseUntil != null && leaseUntil.toInstant().isAfter(now))
                            || (nextAttempt != null && nextAttempt.toInstant().isAfter(now))) {
                        return new InboxLease(InboxOutcome.BUSY, consumerName, workerId,
                                row.getLong("fencing_token"), digest);
                    }
                    long previousFence = row.getLong("fencing_token");
                    try (PreparedStatement update = connection.prepareStatement("""
                            UPDATE consumer_event_inbox
                               SET lease_owner = ?, lease_until = ?::timestamptz,
                                   fencing_token = fencing_token + 1,
                                   delivery_attempts = delivery_attempts + 1,
                                   next_attempt_at = ?::timestamptz, last_error_code = NULL
                             WHERE tenant_id = ?::uuid AND consumer_name = ?
                               AND source_event_id = ?::uuid AND state = 'processing'
                               AND fencing_token = ?
                            RETURNING fencing_token
                            """)) {
                        update.setString(1, workerId);
                        update.setString(2, now.plus(leaseTtl).toString());
                        update.setString(3, now.toString());
                        update.setString(4, message.tenantId().toString());
                        update.setString(5, consumerName);
                        update.setString(6, message.eventId().toString());
                        update.setLong(7, previousFence);
                        try (ResultSet renewed = update.executeQuery()) {
                            if (!renewed.next()) {
                                throw new OutboxRelay.LeaseLostException(
                                        "consumer inbox lease lost its fencing compare-and-set");
                            }
                            return new InboxLease(InboxOutcome.APPLIED, consumerName, workerId,
                                    renewed.getLong("fencing_token"), digest);
                        }
                    }
                }
            }
        });
    }

    private void applyInbox(InboxLease lease, InboxMessage message, Instant now,
            TransactionalConsumer consumer) {
        transaction(message.tenantId(), "cannot apply consumer inbox event", connection -> {
            try (PreparedStatement select = connection.prepareStatement(INBOX_PROCESS_SELECT_SQL)) {
                bindInboxKey(select, message, lease.consumerName());
                try (ResultSet row = select.executeQuery()) {
                    if (!row.next() || !"processing".equals(row.getString("state"))
                            || !lease.workerId().equals(row.getString("lease_owner"))
                            || lease.fencingToken() != row.getLong("fencing_token")
                            || !lease.payloadDigest().equals(row.getString("payload_sha256"))
                            || row.getTimestamp("lease_until") == null
                            || !row.getTimestamp("lease_until").toInstant().isAfter(now)) {
                        throw new OutboxRelay.LeaseLostException(
                                "consumer inbox lease is expired or superseded");
                    }
                }
            }
            consumer.handle(connection, message);
            try (PreparedStatement update = connection.prepareStatement("""
                    UPDATE consumer_event_inbox
                       SET state = 'processed', processed_at = ?::timestamptz,
                           lease_owner = NULL, lease_until = NULL,
                           next_attempt_at = ?::timestamptz, last_error_code = NULL
                     WHERE tenant_id = ?::uuid AND consumer_name = ?
                       AND source_event_id = ?::uuid AND state = 'processing'
                       AND lease_owner = ? AND fencing_token = ?
                    """)) {
                update.setString(1, now.toString());
                update.setString(2, now.toString());
                update.setString(3, message.tenantId().toString());
                update.setString(4, lease.consumerName());
                update.setString(5, message.eventId().toString());
                update.setString(6, lease.workerId());
                update.setLong(7, lease.fencingToken());
                requireUpdated(update.executeUpdate(),
                        "stale fencing token cannot mark inbox processed");
            }
            return null;
        });
    }

    private void recordInboxFailure(InboxLease lease, InboxMessage message, Instant now,
            Duration retryDelay, String failureCode) {
        transaction(message.tenantId(), "cannot reschedule consumer inbox event", connection -> {
            try (PreparedStatement update = connection.prepareStatement("""
                    UPDATE consumer_event_inbox
                       SET lease_owner = NULL, lease_until = NULL,
                           next_attempt_at = ?::timestamptz, last_error_code = ?
                     WHERE tenant_id = ?::uuid AND consumer_name = ?
                       AND source_event_id = ?::uuid AND state = 'processing'
                       AND lease_owner = ? AND fencing_token = ?
                    """)) {
                update.setString(1, now.plus(retryDelay).toString());
                update.setString(2, safeFailureCode(failureCode));
                update.setString(3, message.tenantId().toString());
                update.setString(4, lease.consumerName());
                update.setString(5, message.eventId().toString());
                update.setString(6, lease.workerId());
                update.setLong(7, lease.fencingToken());
                requireUpdated(update.executeUpdate(),
                        "stale fencing token cannot reschedule consumer inbox");
            }
            return null;
        });
    }

    private static void bindInboxKey(PreparedStatement statement, InboxMessage message,
            String consumerName) throws SQLException {
        statement.setString(1, message.tenantId().toString());
        statement.setString(2, consumerName);
        statement.setString(3, message.eventId().toString());
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private <T> T transaction(UUID tenantId, String failureMessage, SqlWork<T> work) {
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
                throw new EventStoreException(failureMessage, failure);
            }
        } catch (SQLException failure) {
            throw new EventStoreException(failureMessage, failure);
        }
    }

    static void requireUpdated(int updateCount, String message) {
        if (updateCount != 1) {
            throw new OutboxRelay.LeaseLostException(message);
        }
    }

    static String sha256(String payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK is missing SHA-256", impossible);
        }
    }

    private static String safeFailureCode(String value) {
        OutboxRelay.requireText(value, "failureCode");
        if (!value.matches("[A-Za-z0-9_.-]{1,128}")) {
            throw new IllegalArgumentException("failureCode contains unsafe characters");
        }
        return value;
    }

    private static void requirePositive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
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

    public static class EventStoreException extends IllegalStateException {
        @Serial
        private static final long serialVersionUID = 1L;

        public EventStoreException(String message) {
            super(message);
        }

        public EventStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static final class EventIdentityConflictException extends EventStoreException {
        @Serial
        private static final long serialVersionUID = 1L;

        public EventIdentityConflictException(String message) {
            super(message);
        }
    }
}
