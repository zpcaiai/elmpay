package com.elmpay.risk;

/**
 * Synchronous product boundary backed by the durable decision/outbox runtime.
 * Implementations may throw when the service is unavailable; callers must treat that as REVIEW.
 */
@FunctionalInterface
public interface SynchronousRiskGate {
    RiskDecision evaluate(RiskEvaluationRequest request);
}
