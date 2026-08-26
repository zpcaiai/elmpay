package com.elmpay.payment.refund;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Canonical-payload-bound receipt for approval and provider-query actions. */
public record RefundActionReceipt(UUID tenantId, UUID refundId, String operation,
        String idempotencyKey, String requestDigest, String actorId, String reason,
        String ticketId, long resultVersion, Instant completedAt) {
    public RefundActionReceipt {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(refundId, "refundId");
        requireText(operation, "operation");
        requireText(idempotencyKey, "idempotencyKey");
        requireText(actorId, "actorId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        Objects.requireNonNull(completedAt, "completedAt");
        if (requestDigest == null || !requestDigest.matches("[0-9a-f]{64}")
                || resultVersion < 0) {
            throw new IllegalArgumentException("invalid refund action receipt");
        }
    }

    public boolean matches(String expectedOperation, String expectedDigest) {
        return operation.equals(expectedOperation) && requestDigest.equals(expectedDigest);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }
}
