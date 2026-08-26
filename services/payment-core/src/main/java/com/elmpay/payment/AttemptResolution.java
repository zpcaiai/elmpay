package com.elmpay.payment;

import java.time.Instant;
import java.util.Objects;

public record AttemptResolution(AttemptState state, OutcomeClass outcomeClass,
        String responseDigest, String providerRequestId, String providerTransactionId,
        String providerCodeNamespace, String providerCode, Instant finishedAt) {
    public AttemptResolution {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(outcomeClass, "outcomeClass");
        Objects.requireNonNull(responseDigest, "responseDigest");
        Objects.requireNonNull(providerRequestId, "providerRequestId");
        Objects.requireNonNull(providerCodeNamespace, "providerCodeNamespace");
        Objects.requireNonNull(providerCode, "providerCode");
        Objects.requireNonNull(finishedAt, "finishedAt");
        if (state == AttemptState.INITIATED || !responseDigest.matches("[0-9a-f]{64}")
                || providerRequestId.isBlank() || providerCodeNamespace.isBlank()
                || providerCode.isBlank() || state.finalState() != outcomeClass.finalOutcome()) {
            throw new IllegalArgumentException("invalid payment attempt resolution");
        }
    }
}
