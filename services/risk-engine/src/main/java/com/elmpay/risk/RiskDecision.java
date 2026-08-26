package com.elmpay.risk;

import java.time.Instant;
import java.util.List;

/** Complete explainability envelope for a single deterministic decision. */
public record RiskDecision(
        String decisionId,
        String tenantId,
        String requestId,
        RiskAction action,
        List<String> reasonCodes,
        String ruleSetVersion,
        String ruleSetDigest,
        String signalVersion,
        String modelVersion,
        boolean degraded,
        Instant decidedAt) {

    public RiskDecision {
        reasonCodes = List.copyOf(reasonCodes);
    }
}
