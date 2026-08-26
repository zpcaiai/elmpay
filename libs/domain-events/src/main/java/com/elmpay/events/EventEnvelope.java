package com.elmpay.events;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Additive, tenant-bound event envelope used by the transactional outbox. */
public record EventEnvelope(UUID eventId, String eventType, int eventVersion, Instant occurredAt,
        UUID tenantId, UUID projectId, String correlationId, String causationId,
        Map<String, String> data) {
    public EventEnvelope {
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(eventType, "eventType");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(data, "data");
        if (eventVersion < 1 || eventType.isBlank() || correlationId.isBlank()) {
            throw new IllegalArgumentException("invalid event envelope");
        }
        data = Map.copyOf(data);
    }
}
