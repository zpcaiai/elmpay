package com.elmpay.payment;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Durable binding between a non-provider intent action and its idempotent result. */
public record PaymentActionReceipt(UUID tenantId, UUID intentId, String operation,
        String idempotencyKey, String requestDigest, long resultIntentVersion,
        Instant completedAt) {
    public PaymentActionReceipt {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(requestDigest, "requestDigest");
        Objects.requireNonNull(completedAt, "completedAt");
        if (!operation.matches("[A-Z][A-Z0-9_]{2,63}")
                || idempotencyKey.length() < 16
                || !requestDigest.matches("[0-9a-f]{64}")
                || resultIntentVersion < 1) {
            throw new IllegalArgumentException("invalid payment action receipt");
        }
    }

    public boolean matches(String expectedOperation, String expectedDigest) {
        return operation.equals(expectedOperation) && requestDigest.equals(expectedDigest);
    }
}
