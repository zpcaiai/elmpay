package com.elmpay.payment.readmodel;

import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL payment status/timeline projection with atomic checkpoints and rebuilds. */
public final class JdbcPaymentTimeline {
    static final String CHECKPOINT_LOCK_SQL = """
            SELECT last_sequence_no, generation
              FROM payment_projection_checkpoint
             WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND projector_name = ?
             FOR UPDATE
            """;
    static final String SOURCE_EVENTS_SQL = """
            SELECT sequence_no, id, aggregate_id, event_type, event_version,
                   payload::text AS payload_json, correlation_id, created_at
              FROM outbox_event
             WHERE tenant_id = ?::uuid AND project_id = ?::uuid
               AND aggregate_type = 'payment_intent' AND sequence_no > ?
             ORDER BY sequence_no
             LIMIT ?
            """;
    static final String INSERT_TIMELINE_SQL = """
            INSERT INTO payment_timeline_event
              (tenant_id, project_id, payment_intent_id, generation, sequence_no, event_id,
               event_type, event_version, provider, provider_transaction_id, risk_outcome,
               correlation_id, payload, payload_sha256, occurred_at)
            SELECT ?::uuid, ?::uuid, ?::uuid, ?, ?, ?::uuid, ?, ?,
                   document.payload->>'provider',
                   document.payload->>'provider_transaction_id',
                   document.payload->>'risk_outcome',
                   ?, document.payload, ?, ?::timestamptz
              FROM (SELECT ?::jsonb AS payload) document
            ON CONFLICT (tenant_id, project_id, generation, event_id) DO NOTHING
            """;
    static final String UPSERT_STATUS_SQL = """
            INSERT INTO payment_status_read_model
              (tenant_id, project_id, payment_intent_id, state, amount_minor, currency,
               captured_amount_minor, refunded_amount_minor, provider,
               provider_transaction_id, provider_status, risk_outcome,
               last_sequence_no, generation, updated_at)
            SELECT ?::uuid, ?::uuid, ?::uuid,
                   COALESCE(document.payload->>'state', 'unknown'),
                   COALESCE((document.payload->>'amount_minor')::bigint, 0),
                   document.payload->>'currency',
                   COALESCE((document.payload->>'captured_amount_minor')::bigint, 0),
                   COALESCE((document.payload->>'refunded_amount_minor')::bigint, 0),
                   document.payload->>'provider',
                   document.payload->>'provider_transaction_id',
                   document.payload->>'provider_status',
                   document.payload->>'risk_outcome',
                   ?, ?, ?::timestamptz
              FROM (SELECT ?::jsonb AS payload) document
            ON CONFLICT (tenant_id, project_id, payment_intent_id) DO UPDATE
               SET state = CASE WHEN EXCLUDED.state = 'unknown'
                                THEN payment_status_read_model.state ELSE EXCLUDED.state END,
                   amount_minor = CASE WHEN EXCLUDED.amount_minor = 0
                                       THEN payment_status_read_model.amount_minor
                                       ELSE EXCLUDED.amount_minor END,
                   currency = COALESCE(EXCLUDED.currency, payment_status_read_model.currency),
                   captured_amount_minor = GREATEST(EXCLUDED.captured_amount_minor,
                       payment_status_read_model.captured_amount_minor),
                   refunded_amount_minor = GREATEST(EXCLUDED.refunded_amount_minor,
                       payment_status_read_model.refunded_amount_minor),
                   provider = COALESCE(EXCLUDED.provider, payment_status_read_model.provider),
                   provider_transaction_id = COALESCE(EXCLUDED.provider_transaction_id,
                       payment_status_read_model.provider_transaction_id),
                   provider_status = COALESCE(EXCLUDED.provider_status,
                       payment_status_read_model.provider_status),
                   risk_outcome = COALESCE(EXCLUDED.risk_outcome,
                       payment_status_read_model.risk_outcome),
                   last_sequence_no = EXCLUDED.last_sequence_no,
                   generation = EXCLUDED.generation,
                   updated_at = EXCLUDED.updated_at
             WHERE EXCLUDED.generation > payment_status_read_model.generation
                OR (EXCLUDED.generation = payment_status_read_model.generation
                    AND EXCLUDED.last_sequence_no > payment_status_read_model.last_sequence_no)
            """;
    static final String REBUILD_RESET_CHECKPOINT_SQL = """
            UPDATE payment_projection_checkpoint
               SET last_sequence_no = 0, generation = generation + 1,
                   updated_at = ?::timestamptz
             WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND projector_name = ?
            RETURNING generation
            """;
    static final String REBUILD_DELETE_TIMELINE_SQL = """
            DELETE FROM payment_timeline_event
             WHERE tenant_id = ?::uuid AND project_id = ?::uuid
            """;
    static final String REBUILD_DELETE_STATUS_SQL = """
            DELETE FROM payment_status_read_model
             WHERE tenant_id = ?::uuid AND project_id = ?::uuid
            """;

    public record ProjectionResult(int appliedEvents, long checkpoint, long generation,
            boolean caughtUp) {
        public ProjectionResult {
            if (appliedEvents < 0 || checkpoint < 0 || generation <= 0) {
                throw new IllegalArgumentException("invalid projection result");
            }
        }
    }

    public record PaymentStatus(UUID tenantId, UUID projectId, UUID paymentIntentId,
            String state, long amountMinor, String currency, long capturedAmountMinor,
            long refundedAmountMinor, String provider, String providerTransactionId,
            String providerStatus, String riskOutcome, long lastSequenceNo, long generation,
            Instant updatedAt) {
    }

    public record TimelineEntry(long sequenceNo, UUID eventId, String eventType, int eventVersion,
            String provider, String providerTransactionId, String riskOutcome,
            String correlationId, String payloadJson, String payloadSha256, Instant occurredAt) {
    }

    private record Checkpoint(long sequence, long generation) {
    }

    private record SourceEvent(long sequence, UUID eventId, UUID aggregateId, String eventType,
            int eventVersion, String payloadJson, String correlationId, Instant occurredAt) {
    }

    private record Batch(int applied, long checkpoint, boolean caughtUp) {
    }

    private final DataSource dataSource;

    public JdbcPaymentTimeline(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public ProjectionResult projectNextBatch(UUID tenantId, UUID projectId, String projectorName,
            int batchSize, Instant now) {
        validateScope(tenantId, projectId, projectorName, batchSize, now);
        return transaction(tenantId, "cannot project payment timeline", connection -> {
            ensureCheckpoint(connection, tenantId, projectId, projectorName, now);
            Checkpoint checkpoint = lockCheckpoint(connection, tenantId, projectId, projectorName);
            Batch batch = projectBatch(connection, tenantId, projectId, checkpoint.generation(),
                    checkpoint.sequence(), batchSize);
            if (batch.checkpoint() != checkpoint.sequence()) {
                updateCheckpoint(connection, tenantId, projectId, projectorName,
                        batch.checkpoint(), checkpoint.generation(), now);
            }
            return new ProjectionResult(batch.applied(), batch.checkpoint(),
                    checkpoint.generation(), batch.caughtUp());
        });
    }

    /** Rebuilds status, timeline, and checkpoint in one transaction while holding its row lock. */
    public ProjectionResult rebuild(UUID tenantId, UUID projectId, String projectorName,
            int batchSize, Instant now) {
        validateScope(tenantId, projectId, projectorName, batchSize, now);
        return transaction(tenantId, "cannot rebuild payment timeline", connection -> {
            ensureCheckpoint(connection, tenantId, projectId, projectorName, now);
            lockCheckpoint(connection, tenantId, projectId, projectorName);
            deleteScope(connection, REBUILD_DELETE_TIMELINE_SQL, tenantId, projectId);
            deleteScope(connection, REBUILD_DELETE_STATUS_SQL, tenantId, projectId);
            long generation = resetCheckpoint(connection, tenantId, projectId, projectorName, now);
            long checkpoint = 0;
            int total = 0;
            while (true) {
                Batch batch = projectBatch(connection, tenantId, projectId, generation,
                        checkpoint, batchSize);
                total = Math.addExact(total, batch.applied());
                checkpoint = batch.checkpoint();
                updateCheckpoint(connection, tenantId, projectId, projectorName,
                        checkpoint, generation, now);
                if (batch.caughtUp()) {
                    return new ProjectionResult(total, checkpoint, generation, true);
                }
            }
        });
    }

    public Optional<PaymentStatus> findStatus(UUID tenantId, UUID projectId,
            UUID paymentIntentId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(paymentIntentId, "paymentIntentId");
        return transaction(tenantId, "cannot read payment status", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT tenant_id, project_id, payment_intent_id, state, amount_minor, currency,
                           captured_amount_minor, refunded_amount_minor, provider,
                           provider_transaction_id, provider_status, risk_outcome,
                           last_sequence_no, generation, updated_at
                      FROM payment_status_read_model
                     WHERE tenant_id = ?::uuid AND project_id = ?::uuid
                       AND payment_intent_id = ?::uuid
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, paymentIntentId.toString());
                try (ResultSet result = statement.executeQuery()) {
                    return result.next() ? Optional.of(status(result)) : Optional.empty();
                }
            }
        });
    }

    public List<TimelineEntry> timeline(UUID tenantId, UUID projectId, UUID paymentIntentId,
            long afterSequence, int limit) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(paymentIntentId, "paymentIntentId");
        if (afterSequence < 0 || limit < 1 || limit > 100) {
            throw new IllegalArgumentException("invalid timeline cursor or limit");
        }
        return transaction(tenantId, "cannot read payment timeline", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT timeline.sequence_no, timeline.event_id, timeline.event_type,
                           timeline.event_version, timeline.provider,
                           timeline.provider_transaction_id, timeline.risk_outcome,
                           timeline.correlation_id, timeline.payload::text AS payload_json,
                           timeline.payload_sha256, timeline.occurred_at
                      FROM payment_timeline_event timeline
                      JOIN payment_status_read_model status
                        ON status.tenant_id = timeline.tenant_id
                       AND status.project_id = timeline.project_id
                       AND status.payment_intent_id = timeline.payment_intent_id
                       AND status.generation = timeline.generation
                     WHERE timeline.tenant_id = ?::uuid AND timeline.project_id = ?::uuid
                       AND timeline.payment_intent_id = ?::uuid
                       AND timeline.sequence_no > ?
                     ORDER BY timeline.sequence_no
                     LIMIT ?
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, paymentIntentId.toString());
                statement.setLong(4, afterSequence);
                statement.setInt(5, limit);
                List<TimelineEntry> entries = new ArrayList<>();
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        entries.add(new TimelineEntry(result.getLong("sequence_no"),
                                result.getObject("event_id", UUID.class),
                                result.getString("event_type"), result.getInt("event_version"),
                                result.getString("provider"),
                                result.getString("provider_transaction_id"),
                                result.getString("risk_outcome"),
                                result.getString("correlation_id"),
                                result.getString("payload_json"),
                                result.getString("payload_sha256"),
                                result.getTimestamp("occurred_at").toInstant()));
                    }
                }
                return List.copyOf(entries);
            }
        });
    }

    private static Batch projectBatch(Connection connection, UUID tenantId, UUID projectId,
            long generation, long afterSequence, int batchSize) throws SQLException {
        List<SourceEvent> events = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(SOURCE_EVENTS_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setLong(3, afterSequence);
            statement.setInt(4, batchSize);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    events.add(new SourceEvent(result.getLong("sequence_no"),
                            result.getObject("id", UUID.class),
                            result.getObject("aggregate_id", UUID.class),
                            result.getString("event_type"), result.getInt("event_version"),
                            result.getString("payload_json"), result.getString("correlation_id"),
                            result.getTimestamp("created_at").toInstant()));
                }
            }
        }
        int applied = 0;
        long checkpoint = afterSequence;
        for (SourceEvent event : events) {
            applied = Math.addExact(applied,
                    insertTimeline(connection, tenantId, projectId, generation, event));
            upsertStatus(connection, tenantId, projectId, generation, event);
            checkpoint = event.sequence();
        }
        return new Batch(applied, checkpoint, events.size() < batchSize);
    }

    private static int insertTimeline(Connection connection, UUID tenantId, UUID projectId,
            long generation, SourceEvent event) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT_TIMELINE_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, event.aggregateId().toString());
            statement.setLong(4, generation);
            statement.setLong(5, event.sequence());
            statement.setString(6, event.eventId().toString());
            statement.setString(7, event.eventType());
            statement.setInt(8, event.eventVersion());
            statement.setString(9, event.correlationId());
            statement.setString(10, sha256(event.payloadJson()));
            statement.setString(11, event.occurredAt().toString());
            statement.setString(12, event.payloadJson());
            return statement.executeUpdate();
        }
    }

    private static void upsertStatus(Connection connection, UUID tenantId, UUID projectId,
            long generation, SourceEvent event) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPSERT_STATUS_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, event.aggregateId().toString());
            statement.setLong(4, event.sequence());
            statement.setLong(5, generation);
            statement.setString(6, event.occurredAt().toString());
            statement.setString(7, event.payloadJson());
            statement.executeUpdate();
        }
    }

    private static void ensureCheckpoint(Connection connection, UUID tenantId, UUID projectId,
            String projectorName, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO payment_projection_checkpoint
                  (tenant_id, project_id, projector_name, last_sequence_no, generation, updated_at)
                VALUES (?::uuid, ?::uuid, ?, 0, 1, ?::timestamptz)
                ON CONFLICT (tenant_id, project_id, projector_name) DO NOTHING
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, projectorName);
            statement.setString(4, now.toString());
            statement.executeUpdate();
        }
    }

    private static Checkpoint lockCheckpoint(Connection connection, UUID tenantId, UUID projectId,
            String projectorName) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(CHECKPOINT_LOCK_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, projectorName);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new ProjectionException("projection checkpoint is missing");
                }
                return new Checkpoint(result.getLong("last_sequence_no"),
                        result.getLong("generation"));
            }
        }
    }

    private static void updateCheckpoint(Connection connection, UUID tenantId, UUID projectId,
            String projectorName, long sequence, long generation, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE payment_projection_checkpoint
                   SET last_sequence_no = ?, updated_at = ?::timestamptz
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND projector_name = ?
                   AND generation = ? AND last_sequence_no <= ?
                """)) {
            statement.setLong(1, sequence);
            statement.setString(2, now.toString());
            statement.setString(3, tenantId.toString());
            statement.setString(4, projectId.toString());
            statement.setString(5, projectorName);
            statement.setLong(6, generation);
            statement.setLong(7, sequence);
            requireOne(statement.executeUpdate(), "projection checkpoint was superseded");
        }
    }

    private static long resetCheckpoint(Connection connection, UUID tenantId, UUID projectId,
            String projectorName, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                REBUILD_RESET_CHECKPOINT_SQL)) {
            statement.setString(1, now.toString());
            statement.setString(2, tenantId.toString());
            statement.setString(3, projectId.toString());
            statement.setString(4, projectorName);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new ProjectionException("projection checkpoint reset lost its row lock");
                }
                return result.getLong("generation");
            }
        }
    }

    private static void deleteScope(Connection connection, String sql, UUID tenantId,
            UUID projectId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.executeUpdate();
        }
    }

    private static PaymentStatus status(ResultSet result) throws SQLException {
        Timestamp updated = result.getTimestamp("updated_at");
        return new PaymentStatus(result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("payment_intent_id", UUID.class), result.getString("state"),
                result.getLong("amount_minor"), result.getString("currency"),
                result.getLong("captured_amount_minor"), result.getLong("refunded_amount_minor"),
                result.getString("provider"), result.getString("provider_transaction_id"),
                result.getString("provider_status"), result.getString("risk_outcome"),
                result.getLong("last_sequence_no"), result.getLong("generation"),
                updated.toInstant());
    }

    private static void validateScope(UUID tenantId, UUID projectId, String projectorName,
            int batchSize, Instant now) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(now, "now");
        if (projectorName == null || projectorName.isBlank() || projectorName.length() > 128) {
            throw new IllegalArgumentException("invalid projectorName");
        }
        if (batchSize < 1 || batchSize > 1_000) {
            throw new IllegalArgumentException("batchSize must be between 1 and 1000");
        }
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
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new ProjectionException(failureMessage, failure);
            }
        } catch (SQLException failure) {
            throw new ProjectionException(failureMessage, failure);
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

    static void requireOne(int count, String message) {
        if (count != 1) {
            throw new ProjectionException(message);
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
        T execute(Connection connection) throws SQLException;
    }

    public static final class ProjectionException extends IllegalStateException {
        @Serial
        private static final long serialVersionUID = 1L;

        public ProjectionException(String message) {
            super(message);
        }

        public ProjectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
