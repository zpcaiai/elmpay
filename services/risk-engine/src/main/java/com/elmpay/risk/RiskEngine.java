package com.elmpay.risk;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;

/** Deterministic rules with an explicit, fail-closed model degradation path. */
public final class RiskEngine {
    private final Clock clock;
    private final Duration maximumSignalAge;
    private final double modelReviewThreshold;
    private final double modelBlockThreshold;

    public RiskEngine(
            Clock clock,
            Duration maximumSignalAge,
            double modelReviewThreshold,
            double modelBlockThreshold) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maximumSignalAge = Objects.requireNonNull(maximumSignalAge, "maximumSignalAge");
        if (maximumSignalAge.isNegative() || maximumSignalAge.isZero()) {
            throw new IllegalArgumentException("maximumSignalAge must be positive");
        }
        if (!(0.0 <= modelReviewThreshold
                && modelReviewThreshold < modelBlockThreshold
                && modelBlockThreshold <= 1.0)) {
            throw new IllegalArgumentException("model thresholds must satisfy 0 <= review < block <= 1");
        }
        this.modelReviewThreshold = modelReviewThreshold;
        this.modelBlockThreshold = modelBlockThreshold;
    }

    public RiskDecision decide(
            RiskRequest request,
            SignalSnapshot signals,
            RuleSet ruleSet,
            ModelScorer modelScorer) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(signals, "signals");
        Objects.requireNonNull(ruleSet, "ruleSet");
        Objects.requireNonNull(modelScorer, "modelScorer");
        if (!request.tenantId().equals(signals.tenantId())
                || !request.tenantId().equals(ruleSet.tenantId())) {
            throw new SecurityException("cross-tenant risk inputs are forbidden");
        }

        Instant now = clock.instant();
        var reasons = new LinkedHashSet<String>();
        RiskAction action = RiskAction.APPROVE;
        boolean degraded = false;
        String modelVersion = "not-evaluated";

        if (ruleSet.activatedAt().isAfter(now)) {
            action = RiskAction.REVIEW;
            degraded = true;
            reasons.add("RULESET_NOT_ACTIVE");
        } else if (request.occurredAt().isAfter(now.plus(Duration.ofMinutes(5)))) {
            action = RiskAction.REVIEW;
            degraded = true;
            reasons.add("REQUEST_TIME_INVALID");
        } else if (signals.collectedAt().isAfter(now)
                || !signals.expiresAt().isAfter(now)
                || signals.collectedAt().isBefore(now.minus(maximumSignalAge))) {
            action = RiskAction.REVIEW;
            degraded = true;
            reasons.add("SIGNALS_STALE");
        } else {
            for (RiskRule rule : ruleSet.rules()) {
                if (!signals.values().containsKey(rule.signal())) {
                    action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                    degraded = true;
                    reasons.add("SIGNAL_MISSING_" + sanitize(rule.signal()));
                } else if (rule.matches(signals.values())) {
                    action = RiskAction.mostRestrictive(action, rule.action());
                    reasons.add(rule.reasonCode());
                }
            }

            try {
                ModelScorer.ModelScore modelScore = Objects.requireNonNull(
                        modelScorer.score(request, signals), "model score");
                modelVersion = modelScore.version();
                if (!modelScore.available()) {
                    action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                    degraded = true;
                    reasons.add("MODEL_DEGRADED");
                    reasons.add(modelScore.explanationCode());
                } else if (modelScore.score() >= modelBlockThreshold) {
                    action = RiskAction.BLOCK;
                    reasons.add("MODEL_BLOCK_THRESHOLD");
                    reasons.add(modelScore.explanationCode());
                } else if (modelScore.score() >= modelReviewThreshold) {
                    action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                    reasons.add("MODEL_REVIEW_THRESHOLD");
                    reasons.add(modelScore.explanationCode());
                }
            } catch (RuntimeException exception) {
                action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                degraded = true;
                modelVersion = "error";
                reasons.add("MODEL_DEGRADED");
                reasons.add("MODEL_EXECUTION_ERROR");
            }
        }

        if (reasons.isEmpty()) {
            reasons.add("NO_RISK_INDICATOR_MATCHED");
        }
        String decisionId = digest(request.requestId(), ruleSet.digest(), signals.version(),
                modelVersion, action.name(), String.join(",", reasons));
        return new RiskDecision(
                decisionId,
                request.tenantId(),
                request.requestId(),
                action,
                reasons.stream().toList(),
                ruleSet.version(),
                ruleSet.digest(),
                signals.version(),
                modelVersion,
                degraded,
                now);
    }

    private static String sanitize(String value) {
        String sanitized = value.toUpperCase().replaceAll("[^A-Z0-9]+", "_");
        return sanitized.replaceAll("^_+|_+$", "");
    }

    private static String digest(String... values) {
        return CanonicalDigest.sha256(java.util.List.of(values));
    }
}
