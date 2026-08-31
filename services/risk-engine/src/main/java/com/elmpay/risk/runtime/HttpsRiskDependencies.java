package com.elmpay.risk.runtime;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.CanonicalDigest;
import com.elmpay.risk.ModelScorer;
import com.elmpay.risk.RiskRequest;
import com.elmpay.risk.RiskRule;
import com.elmpay.risk.SignalSnapshot;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Strict request-bound HTTPS clients for governed signal and model services. */
public final class HttpsRiskDependencies {
    public interface Transport {
        StrictHttpsTransport.Response post(URI endpoint, byte[] body);
        StrictHttpsTransport.Response get(URI endpoint);
    }

    private HttpsRiskDependencies() { }

    public static SignalProvider signal(URI endpoint, URI readiness,
            StrictHttpsTransport transport, Clock clock) {
        return signal(endpoint, readiness, adapter(transport), clock);
    }

    public static SignalProvider signal(URI endpoint, URI readiness,
            Transport transport, Clock clock) {
        requirePath(endpoint, "/v1/risk/signals");
        requirePath(readiness, "/health/ready");
        requireSameOrigin(endpoint, readiness);
        return new Signal(endpoint, readiness, transport, clock);
    }

    public static ModelProvider model(URI endpoint, URI readiness,
            StrictHttpsTransport transport, Clock clock) {
        return model(endpoint, readiness, adapter(transport), clock);
    }

    public static ModelProvider model(URI endpoint, URI readiness,
            Transport transport, Clock clock) {
        requirePath(endpoint, "/v1/risk/model-score");
        requirePath(readiness, "/health/ready");
        requireSameOrigin(endpoint, readiness);
        return new Model(endpoint, readiness, transport, clock);
    }

    private record Signal(URI endpoint, URI readiness, Transport transport,
            Clock clock) implements SignalProvider {
        private static final Set<String> FIELDS = Set.of("tenantId", "projectId", "requestId",
                "version", "collectedAt", "expiresAt", "values", "contentDigest");

        @Override
        public SignalSnapshot fetch(RiskRequest request) {
            Map<String, Object> body = requestDocument(request);
            byte[] encodedRequest = StrictJson.canonical(body).getBytes(StandardCharsets.UTF_8);
            try (StrictHttpsTransport.Response response = transport.post(endpoint,
                    encodedRequest)) {
                Map<String, Object> value = responseObject(response, "signal");
                exact(value, FIELDS, "signal");
                bind(request, value);
                Object rawValues = value.get("values");
                if (!(rawValues instanceof Map<?, ?> entries) || entries.size() > 128) {
                    throw new SecurityException("signal values schema is invalid");
                }
                Map<String, BigDecimal> signals = new LinkedHashMap<>();
                entries.forEach((key, raw) -> {
                    if (!(key instanceof String name)
                            || !name.matches("[A-Za-z][A-Za-z0-9_.-]{0,127}")
                            || !(raw instanceof String decimal)) {
                        throw new SecurityException("signal value is not a named exact decimal");
                    }
                    signals.put(name, RiskRule.canonical(parseDecimal(decimal, "signal value")));
                });
                SignalSnapshot snapshot = new SignalSnapshot(text(value, "tenantId"),
                        text(value, "projectId"), text(value, "requestId"),
                        text(value, "version"), instant(value, "collectedAt"),
                        instant(value, "expiresAt"), signals, digest(value, "contentDigest"));
                Instant now = clock.instant();
                if (!snapshot.expiresAt().isAfter(now) || snapshot.collectedAt().isAfter(now)) {
                    throw new SecurityException("signal snapshot is outside its validity window");
                }
                return snapshot;
            } finally {
                java.util.Arrays.fill(encodedRequest, (byte) 0);
            }
        }

        @Override public boolean ready() {
            return HttpsRiskDependencies.readiness(transport, readiness);
        }
    }

    private record Model(URI endpoint, URI readiness, Transport transport,
            Clock clock) implements ModelProvider {
        private static final Set<String> FIELDS = Set.of("tenantId", "projectId", "requestId",
                "requestDigest", "signalDigest", "version", "score", "explanationCode",
                "expiresAt", "contentDigest");

        @Override
        public ModelScorer.ModelScore score(RiskRequest request, SignalSnapshot signals) {
            Map<String, Object> body = new LinkedHashMap<>(requestDocument(request));
            body.put("signalVersion", signals.version());
            body.put("signalDigest", signals.contentDigest());
            body.put("signals", signals.values().entrySet().stream().collect(
                    java.util.stream.Collectors.toMap(Map.Entry::getKey,
                            entry -> entry.getValue().toPlainString())));
            byte[] encodedRequest = StrictJson.canonical(body).getBytes(StandardCharsets.UTF_8);
            try (StrictHttpsTransport.Response response = transport.post(endpoint,
                    encodedRequest)) {
                Map<String, Object> value = responseObject(response, "model");
                exact(value, FIELDS, "model");
                bind(request, value);
                if (!request.requestDigest().equals(text(value, "requestDigest"))
                        || !signals.contentDigest().equals(text(value, "signalDigest"))) {
                    throw new SecurityException("model response digest binding is invalid");
                }
                BigDecimal score = RiskRule.canonical(
                        parseDecimal(text(value, "score"), "model score"));
                String version = text(value, "version");
                String explanation = text(value, "explanationCode");
                Instant expires = instant(value, "expiresAt");
                String expected = CanonicalDigest.sha256(List.of(request.tenantId(),
                        request.projectId(), request.requestId(), request.requestDigest(),
                        signals.contentDigest(), version, score.toPlainString(), explanation,
                        expires.toString()));
                String supplied = digest(value, "contentDigest");
                if (!expected.equals(supplied) || !expires.isAfter(clock.instant())) {
                    throw new SecurityException("model result digest or validity window is invalid");
                }
                return new ModelScorer.ModelScore(true, version, supplied, score, explanation);
            } finally {
                java.util.Arrays.fill(encodedRequest, (byte) 0);
            }
        }

        @Override public boolean ready() {
            return HttpsRiskDependencies.readiness(transport, readiness);
        }
    }

    private static Map<String, Object> requestDocument(RiskRequest request) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("tenantId", request.tenantId());
        value.put("projectId", request.projectId());
        value.put("requestId", request.requestId());
        value.put("requestDigest", request.requestDigest());
        value.put("operation", request.operation().name());
        value.put("subjectDigest", request.subjectDigest());
        value.put("amountMinor", request.amountMinor());
        value.put("currency", request.currency());
        value.put("occurredAt", request.occurredAt().toString());
        value.put("attributes", request.attributes());
        return Map.copyOf(value);
    }

    private static Map<String, Object> responseObject(StrictHttpsTransport.Response response,
            String dependency) {
        if (response.status() != 200 || !"application/json".equals(response.contentType())) {
            throw new IllegalStateException(dependency + " dependency returned an unsafe response");
        }
        byte[] body = response.body();
        try {
            return StrictJson.object(strictUtf8(body));
        } finally {
            java.util.Arrays.fill(body, (byte) 0);
        }
    }

    private static void bind(RiskRequest request, Map<String, Object> value) {
        if (!request.tenantId().equals(text(value, "tenantId"))
                || !request.projectId().equals(text(value, "projectId"))
                || !request.requestId().equals(text(value, "requestId"))) {
            throw new SecurityException("dependency response binding is invalid");
        }
    }

    private static boolean readiness(Transport transport, URI endpoint) {
        try (StrictHttpsTransport.Response response = transport.get(endpoint)) {
            if (response.status() != 200 || !"application/json".equals(response.contentType())) {
                return false;
            }
            byte[] body = response.body();
            try {
                Map<String, Object> document = StrictJson.object(strictUtf8(body));
                return Set.of("status").equals(document.keySet())
                        && "ready".equals(document.get("status"));
            } finally {
                java.util.Arrays.fill(body, (byte) 0);
            }
        } catch (RuntimeException unavailable) {
            return false;
        }
    }

    private static String strictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(value)).toString();
        } catch (java.nio.charset.CharacterCodingException invalid) {
            throw new SecurityException("dependency response is not canonical UTF-8", invalid);
        }
    }

    private static Transport adapter(StrictHttpsTransport transport) {
        Objects.requireNonNull(transport, "transport");
        return new Transport() {
            @Override public StrictHttpsTransport.Response post(URI endpoint, byte[] body) {
                return transport.post(endpoint, body, Map.of());
            }
            @Override public StrictHttpsTransport.Response get(URI endpoint) {
                return transport.get(endpoint);
            }
        };
    }

    private static BigDecimal parseDecimal(String value, String label) {
        if (!value.matches("-?(?:0|[1-9][0-9]{0,37})(?:\\.[0-9]{1,18})?")) {
            throw new SecurityException(label + " is not a canonical finite decimal string");
        }
        try {
            return new BigDecimal(value);
        } catch (NumberFormatException failure) {
            throw new SecurityException(label + " is invalid", failure);
        }
    }

    private static void exact(Map<String, Object> value, Set<String> fields, String label) {
        if (!fields.equals(value.keySet())) throw new SecurityException(label + " schema is invalid");
    }

    private static String text(Map<String, Object> value, String key) {
        Object raw = value.get(key);
        if (!(raw instanceof String text) || text.isBlank() || text.length() > 512) {
            throw new SecurityException("dependency field is invalid: " + key);
        }
        return text;
    }

    private static String digest(Map<String, Object> value, String key) {
        String digest = text(value, key);
        if (!digest.matches("[0-9a-f]{64}")) throw new SecurityException(key + " is not a digest");
        return digest;
    }

    private static Instant instant(Map<String, Object> value, String key) {
        try {
            return Instant.parse(text(value, key));
        } catch (RuntimeException failure) {
            throw new SecurityException(key + " is not an instant", failure);
        }
    }

    private static void requirePath(URI value, String path) {
        StrictHttpsTransport.exactHttps(value);
        if (!path.equals(value.getRawPath())) throw new IllegalArgumentException("unexpected endpoint path");
    }

    private static void requireSameOrigin(URI left, URI right) {
        int leftPort = left.getPort() < 0 ? 443 : left.getPort();
        int rightPort = right.getPort() < 0 ? 443 : right.getPort();
        if (!left.getHost().equalsIgnoreCase(right.getHost()) || leftPort != rightPort) {
            throw new IllegalArgumentException("dependency readiness must use the configured origin");
        }
    }
}
