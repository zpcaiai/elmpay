package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskOperation;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

final class RemoteSynchronousRiskGateTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final URI ENDPOINT = URI.create("https://risk.svc.example/v1/risk/decisions");

    @Test
    void nonceAndDecisionAreExactlyBound() {
        FakeTransport transport = new FakeTransport(false);
        var decision = gate(transport).evaluate(request());
        assertEquals(RiskAction.APPROVE, decision.action());
        assertEquals(List.of("/v1/risk/nonces", "/v1/risk/decisions"), transport.paths);
        assertTrue(transport.requestBodies.stream()
                .allMatch(RemoteSynchronousRiskGateTest::zeroed));
        for (RemoteSynchronousRiskGate.Response response : transport.responses) {
            assertThrows(IllegalStateException.class, response::body);
        }

        assertEquals(RiskAction.REVIEW, gate(new FakeTransport(true)).evaluate(request()).action());
    }

    @Test
    void nonceAndDecisionConsumeOneMonotonicDeadlineWithoutRestartingBudget() {
        AtomicLong monotonic = new AtomicLong(1_000_000_000L);
        FakeTransport transport = new FakeTransport(false) {
            @Override
            public RemoteSynchronousRiskGate.Response post(URI endpoint, byte[] body,
                    Duration remainingTimeout) {
                remainingBudgets.add(remainingTimeout);
                RemoteSynchronousRiskGate.Response response = super.post(endpoint, body);
                monotonic.addAndGet(Duration.ofMillis(
                        endpoint.getPath().endsWith("/nonces") ? 100 : 50).toNanos());
                return response;
            }
        };
        var decision = new RemoteSynchronousRiskGate(ENDPOINT, fixed(), transport,
                Duration.ofMillis(300), monotonic::get).evaluate(request());

        assertEquals(RiskAction.APPROVE, decision.action());
        assertEquals(Duration.ofMillis(300), transport.remainingBudgets.get(0));
        assertEquals(Duration.ofMillis(200), transport.remainingBudgets.get(1));

        AtomicLong exhausted = new AtomicLong(1_000_000_000L);
        FakeTransport slowNonce = new FakeTransport(false) {
            @Override
            public RemoteSynchronousRiskGate.Response post(URI endpoint, byte[] body,
                    Duration remainingTimeout) {
                RemoteSynchronousRiskGate.Response response = super.post(endpoint, body);
                exhausted.addAndGet(Duration.ofMillis(301).toNanos());
                return response;
            }
        };
        assertEquals(RiskAction.REVIEW, new RemoteSynchronousRiskGate(
                ENDPOINT, fixed(), slowNonce, Duration.ofMillis(300), exhausted::get)
                .evaluate(request()).action());
        assertEquals(List.of("/v1/risk/nonces"), slowNonce.paths);
    }

    @Test
    void transportFailureRedirectAndOversizeFailClosed() {
        assertEquals(RiskAction.REVIEW, gate((endpoint, body) -> {
            throw new IllegalStateException("timeout");
        }).evaluate(request()).action());
        assertEquals(RiskAction.REVIEW, gate((endpoint, body) -> new RemoteSynchronousRiskGate.Response(
                307, "application/json", "{}".getBytes(StandardCharsets.UTF_8)))
                .evaluate(request()).action());
        assertEquals(RiskAction.REVIEW, gate((endpoint, body) -> new RemoteSynchronousRiskGate.Response(
                201, "application/json", new byte[128 * 1024 + 1])).evaluate(request()).action());
        assertEquals(RiskAction.REVIEW, gate((endpoint, body) ->
                new RemoteSynchronousRiskGate.Response(201, "application/json",
                        new byte[] {'{', '"', 'x', '"', ':', '"', (byte) 0xc3, '"', '}'}))
                .evaluate(request()).action());
    }

    @Test
    void endpointMustBeExactHttpsWithoutQueryOrCredentials() {
        assertThrows(IllegalArgumentException.class, () -> new RemoteSynchronousRiskGate(
                URI.create("http://127.0.0.1/v1/risk/decisions"), fixed(), new FakeTransport(false)));
        assertThrows(IllegalArgumentException.class, () -> new RemoteSynchronousRiskGate(
                URI.create("https://user@risk.example/v1/risk/decisions"), fixed(),
                new FakeTransport(false)));
        assertThrows(IllegalArgumentException.class, () -> new RemoteSynchronousRiskGate(
                URI.create("https://risk.example/v1/risk/decisions?tls=false"), fixed(),
                new FakeTransport(false)));
    }

    private static RemoteSynchronousRiskGate gate(RemoteSynchronousRiskGate.Transport transport) {
        return new RemoteSynchronousRiskGate(ENDPOINT, fixed(), transport);
    }

    private static Clock fixed() { return Clock.fixed(NOW, ZoneOffset.UTC); }

    private static RiskEvaluationRequest request() {
        return new RiskEvaluationRequest("10000000-0000-0000-0000-000000000001",
                "20000000-0000-0000-0000-000000000001", "PAYMENT_CREATE:key-1",
                RiskOperation.PAYMENT_CREATE, "merchant-a", 100, "USD", NOW,
                Map.of("channel", "api"));
    }

    private static boolean zeroed(byte[] value) {
        for (byte item : value) {
            if (item != 0) return false;
        }
        return true;
    }

    private static class FakeTransport implements RemoteSynchronousRiskGate.Transport {
        private final boolean wrongBinding;
        private final java.util.ArrayList<String> paths = new java.util.ArrayList<>();
        protected final java.util.ArrayList<Duration> remainingBudgets = new java.util.ArrayList<>();
        private final java.util.ArrayList<byte[]> requestBodies = new java.util.ArrayList<>();
        private final java.util.ArrayList<RemoteSynchronousRiskGate.Response> responses =
                new java.util.ArrayList<>();

        private FakeTransport(boolean wrongBinding) { this.wrongBinding = wrongBinding; }

        @Override
        public RemoteSynchronousRiskGate.Response post(URI endpoint, byte[] body) {
            paths.add(endpoint.getPath());
            requestBodies.add(body);
            if (endpoint.getPath().endsWith("/nonces")) {
                byte[] response = StrictJson.canonical(Map.of("nonce", "n".repeat(43),
                        "expiresAt", NOW.plusSeconds(30).toString()))
                        .getBytes(StandardCharsets.UTF_8);
                return track(new RemoteSynchronousRiskGate.Response(
                        201, "application/json", response));
            }
            Map<String, Object> request = StrictJson.object(new String(body, StandardCharsets.UTF_8));
            RiskEvaluationRequest expected = request();
            assertEquals("n".repeat(43), request.get("nonce"));
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("decisionId", "1".repeat(64));
            response.put("tenantId", request.get("tenantId"));
            response.put("projectId", wrongBinding
                    ? "20000000-0000-0000-0000-000000000002" : request.get("projectId"));
            response.put("requestId", request.get("requestId"));
            response.put("requestDigest", request.get("requestDigest"));
            response.put("operation", request.get("operation"));
            response.put("subjectDigest", expected.subjectDigest());
            response.put("action", "APPROVE");
            response.put("reasonCodes", List.of("NO_RISK_INDICATOR_MATCHED"));
            response.put("ruleSetVersion", "rules-1");
            response.put("ruleSetDigest", "3".repeat(64));
            response.put("signalVersion", "signals-1");
            response.put("signalDigest", "4".repeat(64));
            response.put("modelVersion", "model-1");
            response.put("modelDigest", "5".repeat(64));
            response.put("degraded", false);
            response.put("decidedAt", NOW.toString());
            return track(new RemoteSynchronousRiskGate.Response(200, "application/json",
                    StrictJson.canonical(response).getBytes(StandardCharsets.UTF_8)));
        }

        private RemoteSynchronousRiskGate.Response track(
                RemoteSynchronousRiskGate.Response response) {
            responses.add(response);
            return response;
        }
    }
}
