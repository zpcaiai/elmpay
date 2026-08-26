package com.elmpay.observability;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Low-cardinality, non-sensitive correlation context. */
public record TelemetryContext(String traceId, String correlationId, UUID tenantId, UUID projectId,
        String operation, Map<String, String> attributes) {
    public TelemetryContext {
        Objects.requireNonNull(traceId, "traceId");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(attributes, "attributes");
        if (traceId.isBlank() || correlationId.isBlank() || operation.isBlank()) {
            throw new IllegalArgumentException("telemetry identifiers are required");
        }
        attributes = Map.copyOf(attributes);
    }
}
