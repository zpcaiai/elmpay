package com.elmpay.risk;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/** Internal request with raw subjects removed before durable evaluation. */
public record RiskRequest(String tenantId, String projectId, String requestId,
        String requestDigest, RiskOperation operation, String subjectDigest, long amountMinor,
        String currency, Instant occurredAt, Map<String, String> attributes) {
    public RiskRequest {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(currency, "currency");
        Objects.requireNonNull(occurredAt, "occurredAt");
        attributes = Map.copyOf(attributes);
        if (!requestDigest.matches("[0-9a-f]{64}") || !subjectDigest.matches("[0-9a-f]{64}")
                || amountMinor < 0) {
            throw new IllegalArgumentException("risk request digest or amount is invalid");
        }
    }

    public static RiskRequest from(RiskEvaluationRequest request) {
        Objects.requireNonNull(request, "request");
        return new RiskRequest(request.tenantId(), request.projectId(), request.requestId(),
                request.requestDigest(), request.operation(), request.subjectDigest(),
                request.amountMinor(), request.currency(), request.occurredAt(), request.attributes());
    }
}
