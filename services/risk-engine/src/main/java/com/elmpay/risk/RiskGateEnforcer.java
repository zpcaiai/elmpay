package com.elmpay.risk;

import java.util.List;
import java.util.Objects;

/** Shared fail-closed enforcement so every product path applies identical semantics. */
public final class RiskGateEnforcer {
    private RiskGateEnforcer() {
    }

    public static RiskDecision requireApproved(SynchronousRiskGate gate,
            RiskEvaluationRequest request) {
        RiskDecision decision;
        try {
            decision = Objects.requireNonNull(gate.evaluate(request), "risk decision");
        } catch (RiskGateException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new RiskGateException(RiskAction.REVIEW, "unavailable",
                    List.of("RISK_SERVICE_UNAVAILABLE"),
                    "risk decision is unavailable; manual review is required");
        }
        if (!request.tenantId().equals(decision.tenantId())
                || !request.projectId().equals(decision.projectId())
                || !request.requestId().equals(decision.requestId())
                || !request.requestDigest().equals(decision.requestDigest())
                || request.operation() != decision.operation()
                || !request.subjectDigest().equals(decision.subjectDigest())) {
            throw new RiskGateException(RiskAction.REVIEW, "binding-mismatch",
                    List.of("RISK_DECISION_BINDING_MISMATCH"),
                    "risk decision binding is invalid; manual review is required");
        }
        if (decision.action() != RiskAction.APPROVE) {
            throw new RiskGateException(decision.action(), decision.decisionId(),
                    decision.reasonCodes(), decision.action() == RiskAction.BLOCK
                            ? "risk policy blocked the operation"
                            : "risk policy requires manual review");
        }
        return decision;
    }
}
