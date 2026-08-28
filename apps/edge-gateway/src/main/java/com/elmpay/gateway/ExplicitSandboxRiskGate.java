package com.elmpay.gateway;

import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.SynchronousRiskGate;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/** Explicitly selected local-only policy; it is never constructed by the postgres runtime. */
final class ExplicitSandboxRiskGate implements SynchronousRiskGate {
    private final RiskAction action;
    private final Clock clock;

    ExplicitSandboxRiskGate(RiskAction action, Clock clock) {
        this.action = Objects.requireNonNull(action, "action");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (action == RiskAction.BLOCK) {
            throw new IllegalArgumentException("local sandbox policy supports APPROVE or REVIEW");
        }
    }

    @Override
    public RiskDecision evaluate(RiskEvaluationRequest request) {
        String reason = action == RiskAction.APPROVE
                ? "LOCAL_SANDBOX_EXPLICIT_APPROVAL" : "LOCAL_SANDBOX_REVIEW_ALL";
        String decisionId = sha256(request.tenantId() + "\n" + request.requestId()
                + "\n" + action.name());
        return new RiskDecision(decisionId, request.tenantId(), request.requestId(), action,
                List.of(reason), "local-sandbox", sha256("local-sandbox"), "local-sandbox",
                "disabled", action != RiskAction.APPROVE, clock.instant());
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
