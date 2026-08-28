package com.elmpay.payment;

import java.util.Objects;
import java.util.UUID;

public record CaptureCommand(UUID tenantId, UUID intentId, long amountMinor,
        String idempotencyKey, String correlationId) {
    public CaptureCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(correlationId, "correlationId");
        if (correlationId.isBlank()) {
            throw new IllegalArgumentException("invalid capture command");
        }
    }
}
