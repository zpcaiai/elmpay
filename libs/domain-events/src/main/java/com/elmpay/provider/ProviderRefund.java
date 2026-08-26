package com.elmpay.provider;

import com.elmpay.money.Money;
import java.util.Objects;

public record ProviderRefund(String providerRefundId, ProviderOutcome outcome, Money refunded,
        boolean finalOutcome) {
    public ProviderRefund {
        Objects.requireNonNull(outcome, "outcome");
        if (outcome == ProviderOutcome.UNKNOWN && finalOutcome) {
            throw new IllegalArgumentException("unknown refund cannot be final");
        }
    }
}
