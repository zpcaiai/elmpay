package com.elmpay.payment;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** One record per provider call. Raw provider payloads and credentials are never retained. */
public record PaymentAttempt(UUID id, UUID tenantId, UUID intentId, UUID providerAccountId,
        String provider, AttemptOperation operation, int sequence, String requestDigest,
        String idempotencyKey,
        AttemptState state, OutcomeClass outcomeClass, String responseDigest,
        String providerRequestId, String providerTransactionId, String providerCodeNamespace,
        String providerCode, Instant startedAt, Instant finishedAt, String leaseOwner,
        long fencingToken, Instant leaseExpiresAt) {
    public PaymentAttempt {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(requestDigest, "requestDigest");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(leaseOwner, "leaseOwner");
        Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
        if (provider.isBlank() || sequence < 1 || !requestDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("invalid payment attempt");
        }
        if (leaseOwner.isBlank() || leaseOwner.length() > 128 || fencingToken < 1
                || leaseExpiresAt.isBefore(startedAt)) {
            throw new IllegalArgumentException("invalid payment attempt lease");
        }
        if (state == AttemptState.INITIATED && (outcomeClass != null || finishedAt != null)) {
            throw new IllegalArgumentException("initiated attempt cannot contain a resolution");
        }
        if (state != AttemptState.INITIATED && (outcomeClass == null || responseDigest == null
                || providerRequestId == null || providerCodeNamespace == null
                || providerCode == null || finishedAt == null)) {
            throw new IllegalArgumentException("resolved attempt requires normalized evidence");
        }
    }

    public static PaymentAttempt begin(AttemptDraft draft, int sequence) {
        return new PaymentAttempt(UUID.randomUUID(), draft.tenantId(), draft.intentId(),
                draft.providerAccountId(), draft.provider(), draft.operation(), sequence,
                draft.requestDigest(), draft.idempotencyKey(), AttemptState.INITIATED,
                null, null, null, null,
                null, null, draft.startedAt(), null, draft.leaseOwner(), 1,
                draft.leaseExpiresAt());
    }

    public PaymentAttempt resolve(AttemptResolution resolution) {
        if (state != AttemptState.INITIATED && state != AttemptState.PENDING
                && state != AttemptState.UNKNOWN) {
            throw new PaymentCoreException("ATTEMPT_ALREADY_FINAL", "final attempt is immutable");
        }
        return new PaymentAttempt(id, tenantId, intentId, providerAccountId, provider, operation,
                sequence, requestDigest, idempotencyKey, resolution.state(), resolution.outcomeClass(),
                resolution.responseDigest(), resolution.providerRequestId(),
                resolution.providerTransactionId(), resolution.providerCodeNamespace(),
                resolution.providerCode(), startedAt, resolution.finishedAt(), leaseOwner,
                fencingToken, resolution.finishedAt());
    }

    /** Returns the same immutable provider-call snapshot under a newly fenced recovery lease. */
    public PaymentAttempt withLease(String newLeaseOwner, long newFencingToken,
            Instant newLeaseExpiresAt) {
        return new PaymentAttempt(id, tenantId, intentId, providerAccountId, provider, operation,
                sequence, requestDigest, idempotencyKey, state, outcomeClass, responseDigest,
                providerRequestId, providerTransactionId, providerCodeNamespace, providerCode,
                startedAt, finishedAt, newLeaseOwner, newFencingToken, newLeaseExpiresAt);
    }
}
