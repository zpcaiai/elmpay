package com.elmpay.risk;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Canonical product-side request for the durable B80-B83/B87 decision service.
 * Subject identifiers are transported only over the authenticated internal channel; the
 * decision service persists their digest rather than the raw identifier.
 */
public record RiskEvaluationRequest(String tenantId, String requestId,
        RiskOperation operation, String subjectId, long amountMinor, String currency,
        Instant occurredAt, Map<String, String> attributes) {
    public RiskEvaluationRequest {
        requireText(tenantId, "tenantId");
        requireText(requestId, "requestId");
        Objects.requireNonNull(operation, "operation");
        requireText(subjectId, "subjectId");
        if (amountMinor < 0) {
            throw new IllegalArgumentException("amountMinor must be non-negative");
        }
        if (currency == null || !currency.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be ISO-4217 uppercase alpha-3");
        }
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(attributes, "attributes");
        TreeMap<String, String> copy = new TreeMap<>();
        attributes.forEach((key, value) -> {
            requireText(key, "attribute key");
            requireText(value, "attribute value");
            if (key.length() > 128 || value.length() > 512) {
                throw new IllegalArgumentException("risk attributes must be bounded");
            }
            copy.put(key, value);
        });
        if (copy.size() > 32) {
            throw new IllegalArgumentException("risk attributes must contain at most 32 entries");
        }
        attributes = Collections.unmodifiableMap(copy);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
