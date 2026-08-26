package com.elmpay.payment;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record ConfirmationCommand(UUID tenantId, UUID intentId,
        PaymentMethodReference paymentMethod, String idempotencyKey, String correlationId,
        String approvedReturnRouteId, Map<String, String> providerParameters) {
    public ConfirmationCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(paymentMethod, "paymentMethod");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(providerParameters, "providerParameters");
        providerParameters = Map.copyOf(providerParameters);
        if (correlationId.isBlank()) {
            throw new IllegalArgumentException("correlation id is required");
        }
    }
}
