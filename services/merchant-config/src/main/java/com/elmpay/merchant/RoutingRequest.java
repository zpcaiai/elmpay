package com.elmpay.merchant;

import java.util.Objects;
import java.util.UUID;

public record RoutingRequest(UUID tenantId, UUID projectId, UUID merchantId, String method,
        String currency, String region, long amountMinor, String stableSplitKey) {
    public RoutingRequest {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(currency, "currency");
        Objects.requireNonNull(region, "region");
        Objects.requireNonNull(stableSplitKey, "stableSplitKey");
        if (method.isBlank() || !currency.matches("[A-Z]{3}") || region.isBlank()
                || amountMinor <= 0 || stableSplitKey.isBlank()) {
            throw new IllegalArgumentException("invalid routing request");
        }
    }
}
