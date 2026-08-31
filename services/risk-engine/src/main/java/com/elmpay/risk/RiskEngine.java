package com.elmpay.risk;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;

/** Deterministic rules with an explicit, fail-closed model degradation path. */
public final class RiskEngine {
    private final Clock clock;
    private final Duration maximumSignalAge;
    private final BigDecimal modelReviewThreshold;
    private final BigDecimal modelBlockThreshold;

    public RiskEngine(
            Clock clock,
            Duration maximumSignalAge,
            BigDecimal modelReviewThreshold,
            BigDecimal modelBlockThreshold) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maximumSignalAge = Objects.requireNonNull(maximumSignalAge, "maximumSignalAge");
        if (maximumSignalAge.isNegative() || maximumSignalAge.isZero()) {
            throw new IllegalArgumentException("maximumSignalAge must be positive");
        }
        this.modelReviewThreshold = RiskRule.canonical(modelReviewThreshold);
        this.modelBlockThreshold = RiskRule.canonical(modelBlockThreshold);
        if (this.modelReviewThreshold.compareTo(BigDecimal.ZERO) < 0
                || this.modelReviewThreshold.compareTo(this.modelBlockThreshold) >= 0
                || this.modelBlockThreshold.compareTo(BigDecimal.ONE) > 0) {
            throw new IllegalArgumentException("model thresholds must satisfy 0 <= review < block <= 1");
        }
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
                || !request.tenantId().equals(ruleSet.tenantId())
                || !request.projectId().equals(signals.projectId())
                || !request.projectId().equals(ruleSet.projectId())
                || !request.requestId().equals(signals.requestId())) {
            throw new SecurityException("risk inputs are not bound to one tenant/project/request");
        }

        Instant now = clock.instant();
        var reasons = new LinkedHashSet<String>();
        RiskAction action = RiskAction.APPROVE;
        boolean degraded = false;
        String modelVersion = "not-evaluated";
        String modelDigest = CanonicalDigest.sha256(java.util.List.of("not-evaluated"));

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
                modelDigest = modelScore.contentDigest();
                if (!modelScore.available()) {
                    action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                    degraded = true;
                    reasons.add("MODEL_DEGRADED");
                    reasons.add(modelScore.explanationCode());
                } else if (modelScore.score().compareTo(modelBlockThreshold) >= 0) {
                    action = RiskAction.BLOCK;
                    reasons.add("MODEL_BLOCK_THRESHOLD");
                    reasons.add(modelScore.explanationCode());
                } else if (modelScore.score().compareTo(modelReviewThreshold) >= 0) {
                    action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                    reasons.add("MODEL_REVIEW_THRESHOLD");
                    reasons.add(modelScore.explanationCode());
                }
            } catch (RuntimeException exception) {
                action = RiskAction.mostRestrictive(action, RiskAction.REVIEW);
                degraded = true;
                modelVersion = "error";
                modelDigest = CanonicalDigest.sha256(java.util.List.of("model-execution-error"));
                reasons.add("MODEL_DEGRADED");
                reasons.add("MODEL_EXECUTION_ERROR");
            }
        }

        if (reasons.isEmpty()) {
            reasons.add("NO_RISK_INDICATOR_MATCHED");
        }
        String decisionId = digest(request.tenantId(), request.projectId(), request.requestId(),
                request.requestDigest(), ruleSet.digest(), signals.contentDigest(), modelDigest,
                action.name(), String.join(",", reasons));
        return new RiskDecision(
                decisionId,
                request.tenantId(),
                request.projectId(),
                request.requestId(),
                request.requestDigest(),
                request.operation(),
                request.subjectDigest(),
                action,
                reasons.stream().toList(),
                ruleSet.version(),
                ruleSet.digest(),
                signals.version(),
                signals.contentDigest(),
                modelVersion,
                modelDigest,
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
