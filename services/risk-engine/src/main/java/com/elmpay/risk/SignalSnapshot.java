package com.elmpay.risk;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Versioned signal values with an explicit validity window. */
public record SignalSnapshot(
        String tenantId,
        String version,
        Instant collectedAt,
        Instant expiresAt,
        Map<String, Double> values) {

    public SignalSnapshot {
        requireText(tenantId, "tenantId");
        requireText(version, "version");
        Objects.requireNonNull(collectedAt, "collectedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (!expiresAt.isAfter(collectedAt)) {
            throw new IllegalArgumentException("expiresAt must be after collectedAt");
        }
        Objects.requireNonNull(values, "values");
        var copy = new TreeMap<String, Double>();
        values.forEach((key, value) -> {
            requireText(key, "signal name");
            if (value == null || !Double.isFinite(value)) {
                throw new IllegalArgumentException("signal values must be finite");
            }
            copy.put(key, value);
        });
        values = Collections.unmodifiableMap(copy);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
