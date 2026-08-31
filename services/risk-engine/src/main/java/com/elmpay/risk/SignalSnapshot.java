package com.elmpay.risk;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Request-bound, content-addressed signal values with an explicit validity window. */
public record SignalSnapshot(String tenantId, String projectId, String requestId, String version,
        Instant collectedAt, Instant expiresAt, Map<String, BigDecimal> values,
        String contentDigest) {
    public SignalSnapshot(String tenantId, String projectId, String requestId, String version,
            Instant collectedAt, Instant expiresAt, Map<String, BigDecimal> values) {
        this(tenantId, projectId, requestId, version, collectedAt, expiresAt, values,
                digest(tenantId, projectId, requestId, version, collectedAt, expiresAt, values));
    }

    public SignalSnapshot {
        requireText(tenantId, "tenantId");
        requireText(projectId, "projectId");
        requireText(requestId, "requestId");
        requireText(version, "version");
        Objects.requireNonNull(collectedAt, "collectedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (!expiresAt.isAfter(collectedAt)) {
            throw new IllegalArgumentException("signal expiry is invalid");
        }
        TreeMap<String, BigDecimal> copy = new TreeMap<>();
        Objects.requireNonNull(values, "values").forEach((key, value) -> {
            requireText(key, "signal name");
            copy.put(key, RiskRule.canonical(value));
        });
        if (copy.size() > 128) {
            throw new IllegalArgumentException("signal snapshot is too large");
        }
        values = Collections.unmodifiableMap(copy);
        if (!digest(tenantId, projectId, requestId, version, collectedAt, expiresAt, values)
                .equals(contentDigest)) {
            throw new IllegalArgumentException("signal snapshot digest does not match content");
        }
    }

    private static String digest(String tenantId, String projectId, String requestId,
            String version, Instant collectedAt, Instant expiresAt,
            Map<String, BigDecimal> values) {
        var fields = new ArrayList<String>();
        fields.add(tenantId);
        fields.add(projectId);
        fields.add(requestId);
        fields.add(version);
        fields.add(collectedAt.toString());
        fields.add(expiresAt.toString());
        new TreeMap<>(values).forEach((key, value) -> {
            fields.add(key);
            fields.add(RiskRule.canonical(value).toPlainString());
        });
        return CanonicalDigest.sha256(fields);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }
}
