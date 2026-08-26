package com.elmpay.payment.refund;

import java.util.Objects;
import java.util.UUID;

/** Idempotent, audited provider-query command for PROCESSING/UNKNOWN refunds. */
public record RefundRecoveryCommand(UUID tenantId, UUID refundId, String actorId,
        String ticketId, String idempotencyKey, String correlationId) {
    public RefundRecoveryCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(refundId, "refundId");
        requireText(actorId, "actorId");
        requireText(ticketId, "ticketId");
        requireText(idempotencyKey, "idempotencyKey");
        requireText(correlationId, "correlationId");
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }
}
