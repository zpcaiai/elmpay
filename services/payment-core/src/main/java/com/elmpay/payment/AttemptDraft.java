package com.elmpay.payment;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record AttemptDraft(UUID tenantId, UUID intentId, UUID providerAccountId, String provider,
        AttemptOperation operation, long expectedIntentVersion, String requestDigest,
        String idempotencyKey, Instant startedAt, String leaseOwner, Instant leaseExpiresAt,
        long expectedDeltaMinor, String currency, String businessOrderDigest) {
    public AttemptDraft {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(requestDigest, "requestDigest");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(leaseOwner, "leaseOwner");
        Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
        if (provider.isBlank() || expectedIntentVersion < 0
                || !requestDigest.matches("[0-9a-f]{64}")
                || idempotencyKey.length() < 16 || leaseOwner.isBlank()
                || leaseOwner.length() > 128 || !leaseExpiresAt.isAfter(startedAt)) {
            throw new IllegalArgumentException("invalid payment attempt draft");
        }
        if (operation == AttemptOperation.CAPTURE
                && (expectedDeltaMinor <= 0 || currency == null
                    || !currency.matches("[A-Z]{3}") || businessOrderDigest == null
                    || !businessOrderDigest.matches("[0-9a-f]{64}"))) {
            throw new IllegalArgumentException(
                    "capture attempt requires an immutable amount, currency and order digest");
        }
        if (operation != AttemptOperation.CAPTURE && (expectedDeltaMinor != 0
                || currency != null || businessOrderDigest != null)) {
            throw new IllegalArgumentException(
                    "non-capture attempt cannot carry a capture expectation");
        }
    }

    public AttemptDraft(UUID tenantId, UUID intentId, UUID providerAccountId, String provider,
            AttemptOperation operation, long expectedIntentVersion, String requestDigest,
            String idempotencyKey, Instant startedAt, String leaseOwner, Instant leaseExpiresAt) {
        this(tenantId, intentId, providerAccountId, provider, operation, expectedIntentVersion,
                requestDigest, idempotencyKey, startedAt, leaseOwner, leaseExpiresAt,
                0, null, null);
    }
}
