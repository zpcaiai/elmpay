package com.elmpay.risk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RiskEngineTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private final RiskEngine engine = new RiskEngine(
            Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(10), 0.60, 0.90);

    @Test
    void producesVersionedExplainableBlock() {
        RiskDecision decision = engine.decide(
                request("tenant-a"),
                signals("tenant-a", NOW.minusSeconds(10), Map.of("velocity_5m", 9.0)),
                rules("tenant-a"),
                (request, signals) -> new ModelScorer.ModelScore(true, "model-7", 0.2, "MODEL_LOW_RISK"));

        assertEquals(RiskAction.BLOCK, decision.action());
        assertTrue(decision.reasonCodes().contains("VELOCITY_LIMIT"));
        assertEquals("rules-3", decision.ruleSetVersion());
        assertEquals("signals-9", decision.signalVersion());
        assertEquals("model-7", decision.modelVersion());
        assertFalse(decision.degraded());
    }

    @Test
    void failsClosedWhenModelThrows() {
        RiskDecision decision = engine.decide(
                request("tenant-a"),
                signals("tenant-a", NOW.minusSeconds(10), Map.of("velocity_5m", 1.0)),
                rules("tenant-a"),
                (request, signals) -> { throw new IllegalStateException("model offline"); });

        assertEquals(RiskAction.REVIEW, decision.action());
        assertTrue(decision.degraded());
        assertTrue(decision.reasonCodes().contains("MODEL_EXECUTION_ERROR"));
    }

    @Test
    void rejectsCrossTenantInputs() {
        assertThrows(SecurityException.class, () -> engine.decide(
                request("tenant-a"),
                signals("tenant-b", NOW.minusSeconds(10), Map.of("velocity_5m", 1.0)),
                rules("tenant-a"),
                (request, signals) -> new ModelScorer.ModelScore(true, "model-7", 0.1, "MODEL_LOW_RISK")));
    }

    @Test
    void staleSignalsNeverApprove() {
        RiskDecision decision = engine.decide(
                request("tenant-a"),
                signals("tenant-a", NOW.minus(Duration.ofHours(1)), Map.of("velocity_5m", 1.0)),
                rules("tenant-a"),
                (request, signals) -> new ModelScorer.ModelScore(true, "model-7", 0.1, "MODEL_LOW_RISK"));
        assertEquals(RiskAction.REVIEW, decision.action());
        assertTrue(decision.reasonCodes().contains("SIGNALS_STALE"));
    }

    @Test
    void futureRuleSetNeverActivatesEarly() {
        RuleSet future = new RuleSet("tenant-a", "rules-future", NOW.plusSeconds(60), List.of(
                new RiskRule("velocity", "4", 100, "velocity_5m",
                        RiskRule.Operator.GREATER_THAN, 5.0, RiskAction.BLOCK, "VELOCITY_LIMIT")));
        RiskDecision decision = engine.decide(
                request("tenant-a"),
                signals("tenant-a", NOW.minusSeconds(10), Map.of("velocity_5m", 1.0)),
                future,
                (request, signals) -> new ModelScorer.ModelScore(true, "model-7", 0.1, "MODEL_LOW_RISK"));
        assertEquals(RiskAction.REVIEW, decision.action());
        assertTrue(decision.reasonCodes().contains("RULESET_NOT_ACTIVE"));
    }

    private static RiskRequest request(String tenantId) {
        return new RiskRequest(
                tenantId, "req-1", new BigDecimal("12.34"), "USD", NOW, Map.of("channel", "web"));
    }

    private static SignalSnapshot signals(String tenantId, Instant collectedAt, Map<String, Double> values) {
        return new SignalSnapshot(tenantId, "signals-9", collectedAt, NOW.plusSeconds(60), values);
    }

    private static RuleSet rules(String tenantId) {
        return new RuleSet(tenantId, "rules-3", NOW.minusSeconds(60), List.of(
                new RiskRule("velocity", "3", 100, "velocity_5m",
                        RiskRule.Operator.GREATER_THAN, 5.0, RiskAction.BLOCK, "VELOCITY_LIMIT")));
    }
}
