package com.elmpay.payment.refund;

import java.util.Objects;
import java.util.UUID;

/** Server-authenticated request. Device context is a digest, never raw telemetry. */
public record RefundRequestCommand(UUID tenantId, UUID paymentIntentId, long amountMinor,
        RefundReason reason, String requesterId, String deviceContextDigest,
        String idempotencyKey, String correlationId) {
    public RefundRequestCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(paymentIntentId, "paymentIntentId");
        Objects.requireNonNull(reason, "reason");
        requireText(requesterId, "requesterId");
        requireText(deviceContextDigest, "deviceContextDigest");
        requireText(idempotencyKey, "idempotencyKey");
        requireText(correlationId, "correlationId");
        if (amountMinor <= 0) {
            throw new IllegalArgumentException("refund amount must be positive minor units");
        }
        if (!deviceContextDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("deviceContextDigest must be a SHA-256 hex digest");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }
}
