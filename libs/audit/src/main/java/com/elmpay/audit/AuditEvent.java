package com.elmpay.audit;

import com.elmpay.security.CanonicalPayload;
import com.elmpay.security.SensitiveDataGuard;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Append-only audit fact. High-risk actions include reason, ticket and before/after digests. */
public record AuditEvent(UUID id, UUID tenantId, String actorId, String action, String targetType,
        String targetId, String reason, String ticketId, Map<String, Object> before,
        Map<String, Object> after, String correlationId, Instant occurredAt) {
    public AuditEvent {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(targetType, "targetType");
        Objects.requireNonNull(targetId, "targetId");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        before = before == null ? Map.of() : Map.copyOf(before);
        after = after == null ? Map.of() : Map.copyOf(after);
        SensitiveDataGuard.assertSafe(before);
        SensitiveDataGuard.assertSafe(after);
    }

    public String canonicalDigest() {
        return CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("id", id.toString()), Map.entry("tenant_id", tenantId.toString()),
                Map.entry("actor_id", actorId), Map.entry("action", action),
                Map.entry("target_type", targetType), Map.entry("target_id", targetId),
                Map.entry("reason", reason == null ? "" : reason),
                Map.entry("ticket_id", ticketId == null ? "" : ticketId),
                Map.entry("before", before), Map.entry("after", after),
                Map.entry("correlation_id", correlationId),
                Map.entry("occurred_at", occurredAt.toString())));
    }
}
