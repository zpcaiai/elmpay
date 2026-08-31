package com.elmpay.payment.events;

import com.elmpay.security.CanonicalPayload;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Appends one event inside a caller-owned transaction and allocates its aggregate revision in
 * PostgreSQL. The supplied connection is never committed or rolled back by this class.
 */
public final class SemanticOutboxAppender {
    private static final Pattern EVENT_NAME = Pattern.compile(
            "[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*){1,7}");
    private static final Pattern AGGREGATE_TYPE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern TRACE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    private SemanticOutboxAppender() {
    }

    public record EventDraft(UUID tenantId, UUID projectId, String aggregateType,
            UUID aggregateId, String eventName, int eventVersion, Instant occurredAt,
            String traceId, Map<String, Object> payload) {
        public EventDraft {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(aggregateId, "aggregateId");
            Objects.requireNonNull(occurredAt, "occurredAt");
            Objects.requireNonNull(payload, "payload");
            if (aggregateType == null || !AGGREGATE_TYPE.matcher(aggregateType).matches()
                    || eventName == null || !EVENT_NAME.matcher(eventName).matches()
                    || traceId == null || !TRACE_ID.matcher(traceId).matches()
                    || eventVersion < 1) {
                throw new IllegalArgumentException("invalid outbox event identity");
            }
            // Validates key/value types, rejects floating point money and breaks mutable aliases.
            payload = Map.copyOf(payload);
            CanonicalPayload.encode(payload);
        }
    }

    public record AppendResult(UUID eventId, long revision, Instant recordedAt) {
        public AppendResult {
            Objects.requireNonNull(eventId, "eventId");
            Objects.requireNonNull(recordedAt, "recordedAt");
            if (revision < 1) {
                throw new IllegalArgumentException("revision must be positive");
            }
        }
    }

    public static AppendResult append(Connection connection, EventDraft event)
            throws SQLException {
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(event, "event");
        if (connection.getAutoCommit()) {
            throw new IllegalArgumentException("outbox append requires a caller-owned transaction");
        }
        long revision = allocateRevision(connection, event);
        UUID eventId = UUID.randomUUID();
        Map<String, Object> payload = new LinkedHashMap<>(event.payload());
        Object existingRevision = payload.putIfAbsent("aggregate_revision", revision);
        if (existingRevision != null && (!(existingRevision instanceof Number number)
                || number.longValue() != revision)) {
            throw new IllegalArgumentException("payload aggregate_revision conflicts with DB revision");
        }
        String payloadJson = new String(CanonicalPayload.encode(payload), StandardCharsets.UTF_8);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO outbox_event
                  (id, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                   event_version, aggregate_revision, payload, correlation_id, occurred_at,
                   recorded_at, trace_id, created_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?, ?::jsonb, ?, ?,
                        clock_timestamp(), ?, clock_timestamp())
                RETURNING recorded_at
                """)) {
            statement.setString(1, eventId.toString());
            statement.setString(2, event.tenantId().toString());
            statement.setString(3, event.projectId().toString());
            statement.setString(4, event.aggregateType());
            statement.setString(5, event.aggregateId().toString());
            statement.setString(6, event.eventName());
            statement.setInt(7, event.eventVersion());
            statement.setLong(8, revision);
            statement.setString(9, payloadJson);
            statement.setString(10, event.traceId());
            statement.setTimestamp(11, Timestamp.from(event.occurredAt()));
            statement.setString(12, event.traceId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("outbox insert did not return recorded_at");
                }
                return new AppendResult(eventId, revision,
                        result.getTimestamp("recorded_at").toInstant());
            }
        }
    }

    private static long allocateRevision(Connection connection, EventDraft event)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO event_aggregate_revision
                  (tenant_id, aggregate_type, aggregate_id, current_revision, updated_at)
                VALUES (?::uuid, ?, ?::uuid, 1, clock_timestamp())
                ON CONFLICT (tenant_id, aggregate_type, aggregate_id) DO UPDATE
                   SET current_revision = event_aggregate_revision.current_revision + 1,
                       updated_at = clock_timestamp()
                RETURNING current_revision
                """)) {
            statement.setString(1, event.tenantId().toString());
            statement.setString(2, event.aggregateType());
            statement.setString(3, event.aggregateId().toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("aggregate revision allocation returned no row");
                }
                long revision = result.getLong(1);
                if (revision < 1) {
                    throw new SQLException("aggregate revision allocator returned an invalid value");
                }
                return revision;
            }
        }
    }
}
