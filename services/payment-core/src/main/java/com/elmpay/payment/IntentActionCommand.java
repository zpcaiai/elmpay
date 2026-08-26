package com.elmpay.payment;

import java.util.Objects;
import java.util.UUID;

public record IntentActionCommand(UUID tenantId, UUID intentId, String idempotencyKey,
        String correlationId, String reason) {
    public IntentActionCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(reason, "reason");
        if (correlationId.isBlank() || reason.isBlank()) {
            throw new IllegalArgumentException("invalid payment intent action");
        }
    }
}
