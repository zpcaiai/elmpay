package com.elmpay.payment.refund;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Safe, audit-compatible event written in the same transaction as refund state. */
public record RefundOutboxEvent(UUID eventId, UUID tenantId, UUID projectId, UUID refundId,
        String eventType, String correlationId, Map<String, Object> payload, Instant createdAt) {
    public RefundOutboxEvent {
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(refundId, "refundId");
        if (eventType == null || eventType.isBlank()
                || correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("invalid refund outbox event");
        }
        payload = Map.copyOf(Objects.requireNonNull(payload, "payload"));
        Objects.requireNonNull(createdAt, "createdAt");
    }
}
