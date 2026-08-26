package com.elmpay.payment.refund;

import java.util.Objects;
import java.util.UUID;

/** Four-eyes approval command; reason and ticket are mandatory audit facts. */
public record RefundApprovalCommand(UUID tenantId, UUID refundId, String approverId,
        String reason, String ticketId, String idempotencyKey, String correlationId) {
    public RefundApprovalCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(refundId, "refundId");
        requireText(approverId, "approverId");
        requireText(reason, "reason");
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
