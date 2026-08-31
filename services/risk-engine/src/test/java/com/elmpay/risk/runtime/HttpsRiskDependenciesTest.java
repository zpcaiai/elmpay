package com.elmpay.risk.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.CanonicalDigest;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.RiskRequest;
import com.elmpay.risk.SignalSnapshot;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class HttpsRiskDependenciesTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final URI SIGNAL = URI.create("https://signal.example/v1/risk/signals");
    private static final URI MODEL = URI.create("https://model.example/v1/risk/model-score");
    private static final URI SIGNAL_READY = URI.create("https://signal.example/health/ready");
    private static final URI MODEL_READY = URI.create("https://model.example/health/ready");

    @Test
    void signalAndModelResponsesRequireExactBindingsDigestsAndFiniteDecimals() {
        RiskRequest request = request();
        SignalSnapshot expected = new SignalSnapshot(request.tenantId(), request.projectId(),
                request.requestId(), "signal-v1", NOW.minusSeconds(1), NOW.plusSeconds(30),
                Map.of("velocity", new BigDecimal("2.5")));
        var signal = HttpsRiskDependencies.signal(SIGNAL, SIGNAL_READY,
                transport(signalDocument(expected)), fixed());
        SignalSnapshot actual = signal.fetch(request);
        assertEquals(expected.contentDigest(), actual.contentDigest());
        assertTrue(signal.ready());

        String expiry = NOW.plusSeconds(30).toString();
        String modelDigest = CanonicalDigest.sha256(List.of(request.tenantId(),
                request.projectId(), request.requestId(), request.requestDigest(),
                actual.contentDigest(), "model-v1", "0.75", "MODEL_SCORE_HIGH", expiry));
        Map<String, Object> modelDocument = new LinkedHashMap<>();
        modelDocument.put("tenantId", request.tenantId());
        modelDocument.put("projectId", request.projectId());
        modelDocument.put("requestId", request.requestId());
        modelDocument.put("requestDigest", request.requestDigest());
        modelDocument.put("signalDigest", actual.contentDigest());
        modelDocument.put("version", "model-v1");
        modelDocument.put("score", "0.75");
        modelDocument.put("explanationCode", "MODEL_SCORE_HIGH");
        modelDocument.put("expiresAt", expiry);
        modelDocument.put("contentDigest", modelDigest);
        var model = HttpsRiskDependencies.model(MODEL, MODEL_READY,
                transport(modelDocument), fixed());
        assertEquals(new BigDecimal("0.75"), model.score(request, actual).score());
        assertTrue(model.ready());

        modelDocument.put("score", "NaN");
        assertThrows(SecurityException.class, () -> HttpsRiskDependencies.model(MODEL,
                MODEL_READY, transport(modelDocument), fixed()).score(request, actual));
        modelDocument.put("score", "0.75");
        modelDocument.put("tenantId", "10000000-0000-0000-0000-000000000002");
        assertThrows(SecurityException.class, () -> HttpsRiskDependencies.model(MODEL,
                MODEL_READY, transport(modelDocument), fixed()).score(request, actual));
    }

    @Test
    void staleSignalAndUnexpectedSchemaFailClosed() {
        RiskRequest request = request();
        SignalSnapshot stale = new SignalSnapshot(request.tenantId(), request.projectId(),
                request.requestId(), "signal-v1", NOW.minusSeconds(60), NOW.minusSeconds(1),
                Map.of());
        assertThrows(SecurityException.class, () -> HttpsRiskDependencies.signal(SIGNAL,
                SIGNAL_READY, transport(signalDocument(stale)), fixed()).fetch(request));
        Map<String, Object> extended = new LinkedHashMap<>(signalDocument(stale));
        extended.put("untrusted", true);
        assertThrows(SecurityException.class, () -> HttpsRiskDependencies.signal(SIGNAL,
                SIGNAL_READY, transport(extended), fixed()).fetch(request));
    }

    @Test
    void malformedUtf8AndParameterizedContentTypesFailClosed() {
        RiskRequest request = request();
        HttpsRiskDependencies.Transport malformed = new HttpsRiskDependencies.Transport() {
            @Override public StrictHttpsTransport.Response post(URI endpoint, byte[] body) {
                return new StrictHttpsTransport.Response(200, "application/json",
                        new byte[] {'{', (byte) 0xc3, '}'});
            }
            @Override public StrictHttpsTransport.Response get(URI endpoint) {
                return new StrictHttpsTransport.Response(200,
                        "application/json; charset=utf-8", new byte[] {'{', '}'});
            }
        };
        assertThrows(SecurityException.class, () -> HttpsRiskDependencies.signal(SIGNAL,
                SIGNAL_READY, malformed, fixed()).fetch(request));
        assertTrue(!HttpsRiskDependencies.signal(SIGNAL, SIGNAL_READY,
                malformed, fixed()).ready());
    }

    @Test
    void dependencyRequestBytesAreWipedAndResponsesAreClosed() {
        RiskRequest request = request();
        SignalSnapshot expected = new SignalSnapshot(request.tenantId(), request.projectId(),
                request.requestId(), "signal-v1", NOW.minusSeconds(1), NOW.plusSeconds(30),
                Map.of("velocity", new BigDecimal("2.5")));
        TrackingTransport transport = new TrackingTransport(signalDocument(expected));
        var signal = HttpsRiskDependencies.signal(SIGNAL, SIGNAL_READY, transport, fixed());

        signal.fetch(request);
        assertTrue(signal.ready());
        assertTrue(transport.requestBodies.stream().allMatch(HttpsRiskDependenciesTest::zeroed));
        for (StrictHttpsTransport.Response response : transport.responses) {
            assertThrows(IllegalStateException.class, response::body);
        }
    }

    private static Map<String, Object> signalDocument(SignalSnapshot snapshot) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("tenantId", snapshot.tenantId());
        value.put("projectId", snapshot.projectId());
        value.put("requestId", snapshot.requestId());
        value.put("version", snapshot.version());
        value.put("collectedAt", snapshot.collectedAt().toString());
        value.put("expiresAt", snapshot.expiresAt().toString());
        value.put("values", snapshot.values().entrySet().stream().collect(
                java.util.stream.Collectors.toMap(Map.Entry::getKey,
                        entry -> entry.getValue().toPlainString())));
        value.put("contentDigest", snapshot.contentDigest());
        return value;
    }

    private static HttpsRiskDependencies.Transport transport(Map<String, Object> response) {
        byte[] encoded = StrictJson.canonical(response).getBytes(StandardCharsets.UTF_8);
        return new HttpsRiskDependencies.Transport() {
            @Override
            public StrictHttpsTransport.Response post(URI endpoint, byte[] body) {
                return new StrictHttpsTransport.Response(200, "application/json", encoded);
            }
            @Override
            public StrictHttpsTransport.Response get(URI endpoint) {
                byte[] ready = StrictJson.canonical(Map.of("status", "ready"))
                        .getBytes(StandardCharsets.UTF_8);
                return new StrictHttpsTransport.Response(200, "application/json", ready);
            }
        };
    }

    private static final class TrackingTransport implements HttpsRiskDependencies.Transport {
        private final Map<String, Object> document;
        private final List<byte[]> requestBodies = new ArrayList<>();
        private final List<StrictHttpsTransport.Response> responses = new ArrayList<>();

        private TrackingTransport(Map<String, Object> document) {
            this.document = Map.copyOf(document);
        }

        @Override
        public StrictHttpsTransport.Response post(URI endpoint, byte[] body) {
            requestBodies.add(body);
            return response(200, StrictJson.canonical(document).getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public StrictHttpsTransport.Response get(URI endpoint) {
            return response(200, StrictJson.canonical(Map.of("status", "ready"))
                    .getBytes(StandardCharsets.UTF_8));
        }

        private StrictHttpsTransport.Response response(int status, byte[] body) {
            StrictHttpsTransport.Response response = new StrictHttpsTransport.Response(
                    status, "application/json", body);
            responses.add(response);
            return response;
        }
    }

    private static boolean zeroed(byte[] value) {
        for (byte item : value) {
            if (item != 0) return false;
        }
        return true;
    }

    private static RiskRequest request() {
        return RiskRequest.from(new RiskEvaluationRequest(
                "10000000-0000-0000-0000-000000000001",
                "20000000-0000-0000-0000-000000000001", "PAYMENT_CREATE:key-1",
                RiskOperation.PAYMENT_CREATE, "merchant-1", 100, "USD", NOW,
                Map.of("channel", "api")));
    }

    private static Clock fixed() { return Clock.fixed(NOW, ZoneOffset.UTC); }
}
