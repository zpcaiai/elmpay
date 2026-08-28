package com.elmpay.payment.refund;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.elmpay.money.Money;
import com.elmpay.payment.ConfirmationMode;
import com.elmpay.payment.IntentState;
import com.elmpay.payment.PaymentIntent;
import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskDecision;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class SynchronousRiskRefundPolicyTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final UUID TENANT = UUID.fromString("10000000-0000-0000-0000-000000000001");

    @Test
    void durableBlockReviewAndTimeoutAreEnforcedBeforeBaseAutoApproval() {
        assertEquals(RefundRiskDecision.DENY, policy(RiskAction.BLOCK).decide(context()));
        assertEquals(RefundRiskDecision.REQUIRE_APPROVAL,
                policy(RiskAction.REVIEW).decide(context()));
        SynchronousRiskRefundPolicy timeout = new SynchronousRiskRefundPolicy(
                ignored -> RefundRiskDecision.AUTO_APPROVE,
                ignored -> { throw new IllegalStateException("timeout"); });
        assertEquals(RefundRiskDecision.REQUIRE_APPROVAL, timeout.decide(context()));
    }

    @Test
    void mostRestrictiveBasePolicyCannotBeOverriddenByGlobalApproval() {
        SynchronousRiskRefundPolicy policy = new SynchronousRiskRefundPolicy(
                ignored -> RefundRiskDecision.DENY,
                request -> decision(request.tenantId(), request.requestId(), RiskAction.APPROVE));
        assertEquals(RefundRiskDecision.DENY, policy.decide(context()));
    }

    private static SynchronousRiskRefundPolicy policy(RiskAction action) {
        return new SynchronousRiskRefundPolicy(ignored -> RefundRiskDecision.AUTO_APPROVE,
                request -> decision(request.tenantId(), request.requestId(), action));
    }

    private static RiskDecision decision(String tenantId, String requestId, RiskAction action) {
        return new RiskDecision("risk-refund-1", tenantId, requestId, action,
                List.of("TEST_RISK_DECISION"), "rules-1", "a".repeat(64), "signals-1",
                "model-1", action != RiskAction.APPROVE, NOW);
    }

    private static RefundRiskPolicy.Context context() {
        UUID intentId = UUID.fromString("10000000-0000-0000-0000-000000000002");
        PaymentIntent intent = new PaymentIntent(intentId, TENANT, UUID.randomUUID(),
                UUID.randomUUID(), "order-1", Money.of(1_000, "USD"), 1_000, 0,
                IntentState.CAPTURED, Set.of("card"), ConfirmationMode.AUTOMATIC, "US",
                "create-key", NOW.plusSeconds(3600), NOW.minusSeconds(60), NOW, 2);
        RefundRequestCommand command = new RefundRequestCommand(TENANT, intentId, 100,
                RefundReason.CUSTOMER_REQUEST, "support-user", "b".repeat(64),
                "refund-risk-key-1", "correlation-risk-1");
        return new RefundRiskPolicy.Context(intent, command, NOW);
    }
}
