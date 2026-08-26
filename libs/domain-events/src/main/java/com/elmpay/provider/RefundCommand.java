package com.elmpay.provider;

import com.elmpay.money.Money;
import java.util.Objects;
import java.util.UUID;

public record RefundCommand(ProviderRequestContext context, UUID refundId,
        String providerPaymentId, Money amount, String reason) {
    public RefundCommand {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(refundId, "refundId");
        Objects.requireNonNull(providerPaymentId, "providerPaymentId");
        Objects.requireNonNull(amount, "amount");
        Objects.requireNonNull(reason, "reason");
    }
}
