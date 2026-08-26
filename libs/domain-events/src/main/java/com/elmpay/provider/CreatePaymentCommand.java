package com.elmpay.provider;

import com.elmpay.money.Money;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record CreatePaymentCommand(ProviderRequestContext context, UUID paymentIntentId,
        String businessOrderNo, Money amount, String method, String approvedReturnRouteId,
        Map<String, String> providerParameters) {
    public CreatePaymentCommand {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(paymentIntentId, "paymentIntentId");
        Objects.requireNonNull(businessOrderNo, "businessOrderNo");
        Objects.requireNonNull(amount, "amount");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(providerParameters, "providerParameters");
        if (businessOrderNo.isBlank() || method.isBlank()) {
            throw new IllegalArgumentException("payment command fields are required");
        }
        providerParameters = Map.copyOf(providerParameters);
    }
}
