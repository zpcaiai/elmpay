package com.elmpay.provider;

import com.elmpay.money.Money;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record VerifiedProviderEvent(UUID tenantId, UUID merchantAccountId, String providerEventId,
        String eventType, String providerPaymentId, String businessOrderNo, Money amount,
        String signatureKeyId, Instant providerOccurredAt, Map<String, String> canonicalData) {
    public VerifiedProviderEvent {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(merchantAccountId, "merchantAccountId");
        Objects.requireNonNull(providerEventId, "providerEventId");
        Objects.requireNonNull(eventType, "eventType");
        Objects.requireNonNull(signatureKeyId, "signatureKeyId");
        Objects.requireNonNull(providerOccurredAt, "providerOccurredAt");
        Objects.requireNonNull(canonicalData, "canonicalData");
        canonicalData = Map.copyOf(canonicalData);
    }
}
