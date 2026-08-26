package com.elmpay.payment;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record AttemptDraft(UUID tenantId, UUID intentId, UUID providerAccountId, String provider,
        AttemptOperation operation, long expectedIntentVersion, String requestDigest,
        String idempotencyKey, Instant startedAt) {
    public AttemptDraft {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(requestDigest, "requestDigest");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(startedAt, "startedAt");
        if (provider.isBlank() || expectedIntentVersion < 0
                || !requestDigest.matches("[0-9a-f]{64}")
                || idempotencyKey.length() < 16) {
            throw new IllegalArgumentException("invalid payment attempt draft");
        }
    }
}
