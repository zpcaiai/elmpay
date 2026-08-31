package com.elmpay.payment.refund;

import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskGateEnforcer;
import com.elmpay.risk.RiskGateException;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.SynchronousRiskGate;
import java.util.Map;
import java.util.Objects;

/** Combines B65 refund policy with the durable B80-B83/B87 synchronous decision. */
public final class SynchronousRiskRefundPolicy implements RefundRiskPolicy {
    private final RefundRiskPolicy basePolicy;
    private final SynchronousRiskGate riskGate;

    public SynchronousRiskRefundPolicy(RefundRiskPolicy basePolicy,
            SynchronousRiskGate riskGate) {
        this.basePolicy = Objects.requireNonNull(basePolicy, "basePolicy");
        this.riskGate = Objects.requireNonNull(riskGate, "riskGate");
    }

    @Override
    public RefundRiskDecision decide(Context context) {
        Objects.requireNonNull(context, "context");
        RefundRequestCommand command = context.command();
        var intent = context.paymentIntent();
        RefundRiskDecision durableDecision;
        try {
            RiskGateEnforcer.requireApproved(riskGate, new RiskEvaluationRequest(
                    command.tenantId().toString(),
                    intent.projectId().toString(),
                    RiskOperation.REFUND_REQUEST.name() + ":" + command.idempotencyKey(),
                    RiskOperation.REFUND_REQUEST, command.requesterId(), command.amountMinor(),
                    intent.amount().currency().code(), context.evaluatedAt(),
                    Map.of("intentId", intent.id().toString(),
                            "projectId", intent.projectId().toString(),
                            "merchantId", intent.merchantId().toString(),
                            "reason", command.reason().name(),
                            "deviceContextDigest", command.deviceContextDigest())));
            durableDecision = RefundRiskDecision.AUTO_APPROVE;
        } catch (RiskGateException exception) {
            durableDecision = exception.action() == RiskAction.BLOCK
                    ? RefundRiskDecision.DENY : RefundRiskDecision.REQUIRE_APPROVAL;
        }
        return mostRestrictive(durableDecision, basePolicy.decide(context));
    }

    private static RefundRiskDecision mostRestrictive(RefundRiskDecision left,
            RefundRiskDecision right) {
        if (left == RefundRiskDecision.DENY || right == RefundRiskDecision.DENY) {
            return RefundRiskDecision.DENY;
        }
        if (left == RefundRiskDecision.REQUIRE_APPROVAL
                || right == RefundRiskDecision.REQUIRE_APPROVAL) {
            return RefundRiskDecision.REQUIRE_APPROVAL;
        }
        return RefundRiskDecision.AUTO_APPROVE;
    }
}
