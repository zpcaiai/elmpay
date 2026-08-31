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
    private static final String TENANT = "10000000-0000-0000-0000-000000000001";
    private static final String OTHER_TENANT = "10000000-0000-0000-0000-000000000002";
    private static final String PROJECT = "20000000-0000-0000-0000-000000000001";
    private static final String MODEL_DIGEST = "a".repeat(64);
    private final RiskEngine engine = new RiskEngine(Clock.fixed(NOW, ZoneOffset.UTC),
            Duration.ofMinutes(10), new BigDecimal("0.60"), new BigDecimal("0.90"));

    @Test
    void producesVersionedExplainableBlock() {
        RiskDecision decision = engine.decide(request(TENANT),
                signals(TENANT, NOW.minusSeconds(10), Map.of("velocity_5m", decimal("9"))),
                rules(TENANT), (request, signals) -> new ModelScorer.ModelScore(true, "model-7",
                        MODEL_DIGEST, decimal("0.2"), "MODEL_LOW_RISK"));
        assertEquals(RiskAction.BLOCK, decision.action());
        assertTrue(decision.reasonCodes().contains("VELOCITY_LIMIT"));
        assertEquals("rules-3", decision.ruleSetVersion());
        assertEquals("signals-9", decision.signalVersion());
        assertEquals("model-7", decision.modelVersion());
        assertFalse(decision.degraded());
    }

    @Test
    void failsClosedWhenModelThrows() {
        RiskDecision decision = engine.decide(request(TENANT),
                signals(TENANT, NOW.minusSeconds(10), Map.of("velocity_5m", decimal("1"))),
                rules(TENANT), (request, signals) -> { throw new IllegalStateException("offline"); });
        assertEquals(RiskAction.REVIEW, decision.action());
        assertTrue(decision.degraded());
        assertTrue(decision.reasonCodes().contains("MODEL_EXECUTION_ERROR"));
    }

    @Test
    void rejectsCrossTenantAndRequestInputs() {
        assertThrows(SecurityException.class, () -> engine.decide(request(TENANT),
                signals(OTHER_TENANT, NOW.minusSeconds(10), Map.of("velocity_5m", decimal("1"))),
                rules(TENANT), (request, signals) -> ModelScorer.ModelScore.unavailable(
                        "model-7", MODEL_DIGEST, "MODEL_UNAVAILABLE")));
    }

    @Test
    void staleSignalsNeverApprove() {
        RiskDecision decision = engine.decide(request(TENANT), signals(TENANT,
                        NOW.minus(Duration.ofHours(1)), Map.of("velocity_5m", decimal("1"))),
                rules(TENANT), (request, signals) -> new ModelScorer.ModelScore(true, "model-7",
                        MODEL_DIGEST, decimal("0.1"), "MODEL_LOW_RISK"));
        assertEquals(RiskAction.REVIEW, decision.action());
        assertTrue(decision.reasonCodes().contains("SIGNALS_STALE"));
    }

    @Test
    void futureRuleSetNeverActivatesEarly() {
        RuleSet future = new RuleSet(TENANT, PROJECT, "rules-future", NOW.plusSeconds(60),
                List.of(new RiskRule("velocity", "4", 100, "velocity_5m",
                        RiskRule.Operator.GREATER_THAN, decimal("5"), RiskAction.BLOCK,
                        "VELOCITY_LIMIT")));
        RiskDecision decision = engine.decide(request(TENANT),
                signals(TENANT, NOW.minusSeconds(10), Map.of("velocity_5m", decimal("1"))),
                future, (request, signals) -> new ModelScorer.ModelScore(true, "model-7",
                        MODEL_DIGEST, decimal("0.1"), "MODEL_LOW_RISK"));
        assertEquals(RiskAction.REVIEW, decision.action());
        assertTrue(decision.reasonCodes().contains("RULESET_NOT_ACTIVE"));
    }

    private static RiskRequest request(String tenantId) {
        return RiskRequest.from(new RiskEvaluationRequest(tenantId, PROJECT,
                "PAYMENT_CREATE:key-1", RiskOperation.PAYMENT_CREATE, "merchant-1", 1234,
                "USD", NOW, Map.of("channel", "web")));
    }

    private static SignalSnapshot signals(String tenantId, Instant collectedAt,
            Map<String, BigDecimal> values) {
        return new SignalSnapshot(tenantId, PROJECT, "PAYMENT_CREATE:key-1", "signals-9",
                collectedAt, NOW.plusSeconds(60), values);
    }

    private static RuleSet rules(String tenantId) {
        return new RuleSet(tenantId, PROJECT, "rules-3", NOW.minusSeconds(60), List.of(
                new RiskRule("velocity", "3", 100, "velocity_5m",
                        RiskRule.Operator.GREATER_THAN, decimal("5"), RiskAction.BLOCK,
                        "VELOCITY_LIMIT")));
    }

    private static BigDecimal decimal(String value) { return new BigDecimal(value); }
}
