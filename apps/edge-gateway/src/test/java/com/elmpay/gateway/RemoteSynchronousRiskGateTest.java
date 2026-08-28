package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskOperation;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class RemoteSynchronousRiskGateTest {
    private static final byte[] SECRET = "risk-test-secret-that-is-at-least-32-bytes".getBytes(
            StandardCharsets.UTF_8);
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");

    @Test
    void authenticatedResponseIsBoundToTenantRequestAndOperation() throws Exception {
        try (TestServer server = new TestServer(false, false)) {
            var decision = gate(server.uri(), Duration.ofSeconds(1)).evaluate(request());

            assertEquals(RiskAction.APPROVE, decision.action());
            assertTrue(server.signatureVerified);
        }
        try (TestServer server = new TestServer(true, false)) {
            assertEquals(RiskAction.REVIEW,
                    gate(server.uri(), Duration.ofSeconds(1)).evaluate(request()).action());
        }
    }

    @Test
    void timeoutFailsClosedToReview() throws Exception {
        try (TestServer server = new TestServer(false, true)) {
            var decision = gate(server.uri(), Duration.ofMillis(25)).evaluate(request());
            assertEquals(RiskAction.REVIEW, decision.action());
            assertEquals(List.of("RISK_SERVICE_UNAVAILABLE"), decision.reasonCodes());
        }
    }

    private static RemoteSynchronousRiskGate gate(URI endpoint, Duration timeout) {
        return new RemoteSynchronousRiskGate(endpoint, SECRET, timeout,
                Clock.fixed(NOW, ZoneOffset.UTC), true);
    }

    private static RiskEvaluationRequest request() {
        return new RiskEvaluationRequest("tenant-a", "PAYMENT_CREATE:key-1",
                RiskOperation.PAYMENT_CREATE, "merchant-a", 100, "USD", NOW,
                Map.of("channel", "api"));
    }

    private static final class TestServer implements AutoCloseable {
        private final HttpServer server;
        private final boolean wrongBinding;
        private final boolean slow;
        private volatile boolean signatureVerified;

        private TestServer(boolean wrongBinding, boolean slow) throws IOException {
            this.wrongBinding = wrongBinding;
            this.slow = slow;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/v1/risk/decisions", this::handle);
            server.start();
        }

        private URI uri() {
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/v1/risk/decisions");
        }

        private void handle(HttpExchange exchange) throws IOException {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String timestamp = exchange.getRequestHeaders().getFirst("X-Elmpay-Risk-Timestamp");
            String nonce = exchange.getRequestHeaders().getFirst("X-Elmpay-Risk-Nonce");
            String signature = exchange.getRequestHeaders().getFirst("X-Elmpay-Risk-Signature");
            signatureVerified = MessageDigest.isEqual(signature.getBytes(StandardCharsets.UTF_8),
                    hmac(timestamp + "\n" + nonce + "\n" + sha256(body))
                            .getBytes(StandardCharsets.UTF_8));
            if (slow) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            }
            Map<String, Object> request = Json.object(new String(body, StandardCharsets.UTF_8));
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("decisionId", "1".repeat(64));
            response.put("tenantId", wrongBinding ? "tenant-b" : request.get("tenantId"));
            response.put("requestId", request.get("requestId"));
            response.put("operation", request.get("operation"));
            response.put("subjectDigest", "2".repeat(64));
            response.put("action", "APPROVE");
            response.put("reasonCodes", List.of("NO_RISK_INDICATOR_MATCHED"));
            response.put("ruleSetVersion", "rules-1");
            response.put("ruleSetDigest", "3".repeat(64));
            response.put("signalVersion", "signals-1");
            response.put("modelVersion", "model-1");
            response.put("degraded", false);
            response.put("decidedAt", NOW.toString());
            byte[] encoded = Json.stringify(response).getBytes(StandardCharsets.UTF_8);
            try {
                exchange.sendResponseHeaders(200, encoded.length);
                exchange.getResponseBody().write(encoded);
            } catch (IOException ignored) {
                // Expected when the client deliberately times out.
            } finally {
                exchange.close();
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private static String sha256(byte[] body) {
            try {
                return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            } catch (java.security.GeneralSecurityException exception) {
                throw new IllegalStateException(exception);
            }
        }

        private static String hmac(String value) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
                return HexFormat.of().formatHex(
                        mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
            } catch (java.security.GeneralSecurityException exception) {
                throw new IllegalStateException(exception);
            }
        }
    }
}
