package com.elmpay.payment.refund;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Fail-closed B65 policy across amount, payment age, role, device trust, anomaly score
 * and merchant-specific review settings. Signal values must come from trusted services.
 */
public final class RulesRefundRiskPolicy implements RefundRiskPolicy {
    public record Signals(String requesterRole, boolean trustedDevice, int anomalyScore,
            long manualReviewThresholdMinor, Duration maximumRefundAge,
            boolean merchantForcesReview) {
        public Signals {
            if (requesterRole == null || requesterRole.isBlank()
                    || anomalyScore < 0 || anomalyScore > 100
                    || manualReviewThresholdMinor < 1 || maximumRefundAge == null
                    || maximumRefundAge.isNegative() || maximumRefundAge.isZero()) {
                throw new IllegalArgumentException("invalid trusted refund risk signals");
            }
        }
    }

    @FunctionalInterface
    public interface SignalProvider {
        Signals resolve(Context context);
    }

    private static final Set<String> ALLOWED_ROLES = Set.of(
            "support", "finance", "fraud_analyst", "merchant_admin");
    private final SignalProvider signalProvider;
    private final int denyAnomalyScore;
    private final int reviewAnomalyScore;

    public RulesRefundRiskPolicy(SignalProvider signalProvider, int reviewAnomalyScore,
            int denyAnomalyScore) {
        this.signalProvider = Objects.requireNonNull(signalProvider, "signalProvider");
        if (reviewAnomalyScore < 0 || denyAnomalyScore > 100
                || reviewAnomalyScore >= denyAnomalyScore) {
            throw new IllegalArgumentException("invalid anomaly thresholds");
        }
        this.reviewAnomalyScore = reviewAnomalyScore;
        this.denyAnomalyScore = denyAnomalyScore;
    }

    @Override
    public RefundRiskDecision decide(Context context) {
        Signals signals = Objects.requireNonNull(signalProvider.resolve(context),
                "missing refund risk signals");
        if (!ALLOWED_ROLES.contains(signals.requesterRole())
                || signals.anomalyScore() >= denyAnomalyScore
                || context.evaluatedAt().isAfter(
                        context.paymentIntent().createdAt().plus(signals.maximumRefundAge()))) {
            return RefundRiskDecision.DENY;
        }
        if (signals.merchantForcesReview() || !signals.trustedDevice()
                || signals.anomalyScore() >= reviewAnomalyScore
                || context.command().amountMinor() >= signals.manualReviewThresholdMinor()
                || context.command().reason() == RefundReason.FRAUDULENT) {
            return RefundRiskDecision.REQUIRE_APPROVAL;
        }
        return RefundRiskDecision.AUTO_APPROVE;
    }
}
