package com.elmpay.risk;

/** The most restrictive action wins when multiple controls apply. */
public enum RiskAction {
    APPROVE(0),
    REVIEW(1),
    BLOCK(2);

    private final int severity;

    RiskAction(int severity) {
        this.severity = severity;
    }

    public static RiskAction mostRestrictive(RiskAction left, RiskAction right) {
        return left.severity >= right.severity ? left : right;
    }
}
