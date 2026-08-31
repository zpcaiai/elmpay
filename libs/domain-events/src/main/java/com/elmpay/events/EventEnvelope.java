package com.elmpay.events;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Versioned, tenant/project-bound event envelope carried by the transactional outbox. */
public record EventEnvelope(UUID eventId, String eventName, int eventVersion, UUID tenantId,
        UUID projectId, String aggregateType, UUID aggregateId, long revision, Instant occurredAt,
        Instant recordedAt, String traceId, Map<String, Object> payload) {
    private static final Pattern EVENT_NAME = Pattern.compile(
            "[a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*){1,7}");
    private static final Pattern AGGREGATE_TYPE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern TRACE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Set<String> FIELDS = Set.of(
            "event_id", "event_name", "event_version", "tenant_id", "project_id",
            "aggregate_type", "aggregate_id", "revision", "occurred_at", "recorded_at",
            "trace_id", "payload");

    public EventEnvelope {
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(aggregateId, "aggregateId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(recordedAt, "recordedAt");
        Objects.requireNonNull(payload, "payload");
        if (eventName == null || !EVENT_NAME.matcher(eventName).matches()
                || aggregateType == null || !AGGREGATE_TYPE.matcher(aggregateType).matches()
                || traceId == null || !TRACE_ID.matcher(traceId).matches()
                || eventVersion < 1 || revision < 1) {
            throw new IllegalArgumentException("invalid event envelope identity");
        }
        if (occurredAt.isAfter(recordedAt.plusSeconds(300))) {
            throw new IllegalArgumentException("event occurred_at is implausibly after recorded_at");
        }
        // A canonical round trip validates all nested payload values and UTF-16 before copying.
        payload = StrictJson.object(StrictJson.canonical(payload));
    }

    public String canonicalJson() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("event_id", eventId.toString());
        value.put("event_name", eventName);
        value.put("event_version", eventVersion);
        value.put("tenant_id", tenantId.toString());
        value.put("project_id", projectId.toString());
        value.put("aggregate_type", aggregateType);
        value.put("aggregate_id", aggregateId.toString());
        value.put("revision", revision);
        value.put("occurred_at", occurredAt.toString());
        value.put("recorded_at", recordedAt.toString());
        value.put("trace_id", traceId);
        value.put("payload", payload);
        return StrictJson.canonical(value);
    }

    public String aggregateKey() {
        return tenantId + ":" + aggregateType + ":" + aggregateId;
    }

    public static EventEnvelope parse(String json) {
        Map<String, Object> value = StrictJson.object(json);
        if (!value.keySet().equals(FIELDS)) {
            throw new IllegalArgumentException("event envelope has missing or unknown fields");
        }
        Object payloadValue = value.get("payload");
        if (!(payloadValue instanceof Map<?, ?> rawPayload)) {
            throw new IllegalArgumentException("event payload must be an object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) rawPayload;
        return new EventEnvelope(uuid(value, "event_id"), text(value, "event_name"),
                positiveInt(value, "event_version"), uuid(value, "tenant_id"),
                uuid(value, "project_id"), text(value, "aggregate_type"),
                uuid(value, "aggregate_id"), positiveLong(value, "revision"),
                instant(value, "occurred_at"), instant(value, "recorded_at"),
                text(value, "trace_id"), payload);
    }

    private static String text(Map<String, Object> value, String field) {
        Object raw = value.get(field);
        if (!(raw instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(field + " must be a non-empty string");
        }
        return text;
    }

    private static UUID uuid(Map<String, Object> value, String field) {
        try {
            return UUID.fromString(text(value, field));
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException(field + " must be a canonical UUID", failure);
        }
    }

    private static Instant instant(Map<String, Object> value, String field) {
        try {
            return Instant.parse(text(value, field));
        } catch (DateTimeParseException failure) {
            throw new IllegalArgumentException(field + " must be an RFC3339 instant", failure);
        }
    }

    private static int positiveInt(Map<String, Object> value, String field) {
        long number = positiveLong(value, field);
        if (number > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(field + " is outside int32");
        }
        return (int) number;
    }

    private static long positiveLong(Map<String, Object> value, String field) {
        Object raw = value.get(field);
        if (!(raw instanceof Long number) || number <= 0) {
            throw new IllegalArgumentException(field + " must be a positive integer");
        }
        return number;
    }
}
