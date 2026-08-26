package com.elmpay.provider;

import com.elmpay.money.Money;
import java.util.Map;
import java.util.Objects;

public record ProviderPayment(String providerRequestId, String providerPaymentId,
        ProviderOutcome outcome, Money authorized, Money captured, boolean finalOutcome,
        Map<String, String> clientAction) {
    public ProviderPayment {
        Objects.requireNonNull(providerRequestId, "providerRequestId");
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(clientAction, "clientAction");
        clientAction = Map.copyOf(clientAction);
        if (providerRequestId.isBlank()) {
            throw new IllegalArgumentException("provider request id is required");
        }
        if (outcome == ProviderOutcome.UNKNOWN && finalOutcome) {
            throw new IllegalArgumentException("unknown provider outcome cannot be final");
        }
    }
}
