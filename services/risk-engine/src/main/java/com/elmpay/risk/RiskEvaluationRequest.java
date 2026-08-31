package com.elmpay.risk;

import com.elmpay.security.CanonicalPayload;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;

/** Exact tenant/project/request-bound input to the synchronous risk service. */
public record RiskEvaluationRequest(String tenantId, String projectId, String requestId,
        RiskOperation operation, String subjectId, long amountMinor, String currency,
        Instant occurredAt, Map<String, String> attributes) {
    public RiskEvaluationRequest {
        tenantId = canonicalUuid(tenantId, "tenantId");
        projectId = canonicalUuid(projectId, "projectId");
        require(requestId, "requestId", 8, 128, "[A-Za-z0-9][A-Za-z0-9._:-]{7,127}");
        Objects.requireNonNull(operation, "operation");
        require(subjectId, "subjectId", 1, 160, "[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}");
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
            require(key, "attribute key", 1, 64, "[A-Za-z][A-Za-z0-9_.-]{0,63}");
            require(value, "attribute value", 1, 256, "[^\\p{Cntrl}]{1,256}");
            copy.put(key, value);
        });
        if (copy.size() > 32) {
            throw new IllegalArgumentException("risk attributes must contain at most 32 entries");
        }
        attributes = Collections.unmodifiableMap(copy);
    }

    public Map<String, Object> canonicalDocument() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("tenantId", tenantId);
        value.put("projectId", projectId);
        value.put("requestId", requestId);
        value.put("operation", operation.name());
        value.put("subjectId", subjectId);
        value.put("amountMinor", amountMinor);
        value.put("currency", currency);
        value.put("occurredAt", occurredAt);
        value.put("attributes", attributes);
        return Map.copyOf(value);
    }

    public String requestDigest() {
        return CanonicalPayload.sha256Hex(canonicalDocument());
    }

    public String subjectDigest() {
        return CanonicalPayload.sha256Hex(Map.of("tenantId", tenantId, "subjectId", subjectId));
    }

    private static String canonicalUuid(String value, String field) {
        try {
            UUID parsed = UUID.fromString(Objects.requireNonNull(value, field));
            if (!parsed.toString().equals(value)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return value;
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException(field + " must be a canonical UUID", failure);
        }
    }

    private static void require(String value, String field, int minimum, int maximum,
            String expression) {
        if (value == null || value.length() < minimum || value.length() > maximum
                || !value.matches(expression)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }
}
