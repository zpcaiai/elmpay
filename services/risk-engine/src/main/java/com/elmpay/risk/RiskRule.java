package com.elmpay.risk;

import java.util.Map;
import java.util.Objects;

/** A deterministic rule whose identifier and version are included in decision evidence. */
public record RiskRule(
        String id,
        String version,
        int priority,
        String signal,
        Operator operator,
        double threshold,
        RiskAction action,
        String reasonCode) {

    public enum Operator {
        GREATER_THAN,
        GREATER_THAN_OR_EQUAL,
        LESS_THAN,
        LESS_THAN_OR_EQUAL,
        EQUAL
    }

    public RiskRule {
        requireText(id, "id");
        requireText(version, "version");
        requireText(signal, "signal");
        Objects.requireNonNull(operator, "operator");
        if (!Double.isFinite(threshold)) {
            throw new IllegalArgumentException("threshold must be finite");
        }
        Objects.requireNonNull(action, "action");
        if (action == RiskAction.APPROVE) {
            throw new IllegalArgumentException("matching risk rules may only REVIEW or BLOCK");
        }
        if (reasonCode == null || !reasonCode.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("reasonCode must be a stable uppercase code");
        }
    }

    public boolean matches(Map<String, Double> signals) {
        Double value = signals.get(signal);
        if (value == null) {
            return false;
        }
        return switch (operator) {
            case GREATER_THAN -> value > threshold;
            case GREATER_THAN_OR_EQUAL -> value >= threshold;
            case LESS_THAN -> value < threshold;
            case LESS_THAN_OR_EQUAL -> value <= threshold;
            case EQUAL -> Double.compare(value, threshold) == 0;
        };
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
