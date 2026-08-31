package com.elmpay.risk;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Objects;

/** Deterministic rule with exact decimal comparison and explainable outcome. */
public record RiskRule(String id, String version, int priority, String signal,
        Operator operator, BigDecimal threshold, RiskAction action, String reasonCode) {
    public enum Operator {
        GREATER_THAN, GREATER_THAN_OR_EQUAL, LESS_THAN, LESS_THAN_OR_EQUAL, EQUAL
    }

    public RiskRule {
        requireText(id, "id");
        requireText(version, "version");
        requireText(signal, "signal");
        Objects.requireNonNull(operator, "operator");
        threshold = canonical(threshold);
        Objects.requireNonNull(action, "action");
        if (action == RiskAction.APPROVE) {
            throw new IllegalArgumentException("matching risk rules may only REVIEW or BLOCK");
        }
        if (reasonCode == null || !reasonCode.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("reasonCode must be a stable uppercase code");
        }
    }

    public boolean matches(Map<String, BigDecimal> signals) {
        BigDecimal value = signals.get(signal);
        if (value == null) return false;
        int comparison = value.compareTo(threshold);
        return switch (operator) {
            case GREATER_THAN -> comparison > 0;
            case GREATER_THAN_OR_EQUAL -> comparison >= 0;
            case LESS_THAN -> comparison < 0;
            case LESS_THAN_OR_EQUAL -> comparison <= 0;
            case EQUAL -> comparison == 0;
        };
    }

    public static BigDecimal canonical(BigDecimal value) {
        Objects.requireNonNull(value, "decimal value");
        if (value.precision() > 38 || Math.abs(value.scale()) > 18) {
            throw new IllegalArgumentException("risk decimal exceeds precision or scale bounds");
        }
        return value.signum() == 0 ? BigDecimal.ZERO : value.stripTrailingZeros();
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 128) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }
}
