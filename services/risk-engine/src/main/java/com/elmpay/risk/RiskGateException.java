package com.elmpay.risk;

import java.io.Serial;
import java.util.List;

/** A fail-closed product rejection carrying only auditable, non-sensitive decision metadata. */
public final class RiskGateException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;
    private final RiskAction action;
    private final String decisionId;
    private final String reasonCodeCsv;

    public RiskGateException(RiskAction action, String decisionId, List<String> reasonCodes,
            String message) {
        super(message);
        if (action == RiskAction.APPROVE) {
            throw new IllegalArgumentException("an approval is not a risk rejection");
        }
        this.action = java.util.Objects.requireNonNull(action, "action");
        this.decisionId = java.util.Objects.requireNonNull(decisionId, "decisionId");
        this.reasonCodeCsv = String.join(",", List.copyOf(reasonCodes));
    }

    public RiskAction action() {
        return action;
    }

    public String decisionId() {
        return decisionId;
    }

    public List<String> reasonCodes() {
        return reasonCodeCsv.isEmpty() ? List.of() : List.of(reasonCodeCsv.split(",", -1));
    }
}
