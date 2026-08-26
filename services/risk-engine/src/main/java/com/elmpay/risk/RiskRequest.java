package com.elmpay.risk;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Immutable, tenant-scoped input to a risk decision. */
public record RiskRequest(
        String tenantId,
        String requestId,
        BigDecimal amount,
        String currency,
        Instant occurredAt,
        Map<String, String> attributes) {

    public RiskRequest {
        requireText(tenantId, "tenantId");
        requireText(requestId, "requestId");
        Objects.requireNonNull(amount, "amount");
        if (amount.signum() < 0) {
            throw new IllegalArgumentException("amount must be non-negative");
        }
        if (currency == null || !currency.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be ISO-4217 uppercase alpha-3");
        }
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(attributes, "attributes");
        var copy = new TreeMap<String, String>();
        attributes.forEach((key, value) -> {
            requireText(key, "attribute key");
            requireText(value, "attribute value");
            copy.put(key, value);
        });
        attributes = Collections.unmodifiableMap(copy);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
