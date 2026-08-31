package com.elmpay.risk;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Complete explainability and request-binding envelope for one durable decision. */
public record RiskDecision(String decisionId, String tenantId, String projectId, String requestId,
        String requestDigest, RiskOperation operation, String subjectDigest, RiskAction action,
        List<String> reasonCodes, String ruleSetVersion, String ruleSetDigest,
        String signalVersion, String signalDigest, String modelVersion, String modelDigest,
        boolean degraded, Instant decidedAt) {
    public RiskDecision {
        digest(decisionId, "decisionId");
        uuid(tenantId, "tenantId");
        uuid(projectId, "projectId");
        text(requestId, "requestId");
        digest(requestDigest, "requestDigest");
        Objects.requireNonNull(operation, "operation");
        digest(subjectDigest, "subjectDigest");
        Objects.requireNonNull(action, "action");
        text(ruleSetVersion, "ruleSetVersion");
        digest(ruleSetDigest, "ruleSetDigest");
        text(signalVersion, "signalVersion");
        digest(signalDigest, "signalDigest");
        text(modelVersion, "modelVersion");
        digest(modelDigest, "modelDigest");
        Objects.requireNonNull(decidedAt, "decidedAt");
        reasonCodes = List.copyOf(new LinkedHashSet<>(reasonCodes));
        if (reasonCodes.isEmpty() || reasonCodes.size() > 64
                || reasonCodes.stream().anyMatch(code ->
                    code == null || !code.matches("[A-Z][A-Z0-9_]{2,127}"))
                || (action == RiskAction.APPROVE && degraded)) {
            throw new IllegalArgumentException("risk decision reasons or degradation are invalid");
        }
    }

    private static void digest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " is not a SHA-256 digest");
        }
    }

    private static void uuid(String value, String field) {
        try {
            if (!UUID.fromString(value).toString().equals(value)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
        } catch (RuntimeException failure) {
            throw new IllegalArgumentException(field + " is invalid", failure);
        }
    }

    private static void text(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }
}
