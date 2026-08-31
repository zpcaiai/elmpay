package com.elmpay.gateway;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.SynchronousRiskGate;
import com.elmpay.risk.runtime.StrictHttpsTransport;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import javax.net.ssl.SSLContext;

/** TLS 1.3 mTLS nonce+decision client with exact response binding and fail-closed outcomes. */
final class RemoteSynchronousRiskGate implements SynchronousRiskGate {
    interface Transport {
        Response post(URI endpoint, byte[] body);

        default Response post(URI endpoint, byte[] body, Duration remainingTimeout) {
            Objects.requireNonNull(remainingTimeout, "remainingTimeout");
            return post(endpoint, body);
        }
    }
    static final class Response implements AutoCloseable {
        private final int status;
        private final String contentType;
        private byte[] body;

        Response(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = Objects.requireNonNull(contentType, "contentType");
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        int status() {
            return status;
        }

        String contentType() {
            return contentType;
        }

        synchronized byte[] body() {
            if (body == null) {
                throw new IllegalStateException("risk response is closed");
            }
            return body.clone();
        }

        @Override
        public synchronized void close() {
            if (body != null) {
                java.util.Arrays.fill(body, (byte) 0);
                body = null;
            }
        }
    }

    private static final Set<String> NONCE_FIELDS = Set.of("nonce", "expiresAt");
    private static final Set<String> RESPONSE_FIELDS = Set.of("decisionId", "tenantId",
            "projectId", "requestId", "requestDigest", "operation", "subjectDigest", "action",
            "reasonCodes", "ruleSetVersion", "ruleSetDigest", "signalVersion", "signalDigest",
            "modelVersion", "modelDigest", "degraded", "decidedAt");
    private final URI decisionEndpoint;
    private final URI nonceEndpoint;
    private final Clock clock;
    private final Transport transport;
    private final Duration totalTimeout;
    private final LongSupplier monotonicNanos;

    RemoteSynchronousRiskGate(URI endpoint, SSLContext mutualTlsContext, Duration timeout,
            Clock clock) {
        this(endpoint, clock, transport(mutualTlsContext, timeout), timeout, System::nanoTime);
    }

    RemoteSynchronousRiskGate(URI endpoint, Clock clock, Transport transport) {
        this(endpoint, clock, transport, Duration.ofMillis(300), System::nanoTime);
    }

    RemoteSynchronousRiskGate(URI endpoint, Clock clock, Transport transport,
            Duration totalTimeout) {
        this(endpoint, clock, transport, totalTimeout, System::nanoTime);
    }

    RemoteSynchronousRiskGate(URI endpoint, Clock clock, Transport transport,
            Duration totalTimeout, LongSupplier monotonicNanos) {
        this.decisionEndpoint = decisionEndpoint(endpoint);
        this.nonceEndpoint = sibling(this.decisionEndpoint, "/v1/risk/nonces");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.totalTimeout = Objects.requireNonNull(totalTimeout, "totalTimeout");
        this.monotonicNanos = Objects.requireNonNull(monotonicNanos, "monotonicNanos");
        if (totalTimeout.isZero() || totalTimeout.isNegative()
                || totalTimeout.compareTo(Duration.ofMillis(300)) > 0) {
            throw new IllegalArgumentException("risk evaluation timeout must be within 300ms");
        }
    }

    @Override
    public RiskDecision evaluate(RiskEvaluationRequest request) {
        Objects.requireNonNull(request, "request");
        long deadlineNanos = monotonicNanos.getAsLong() + totalTimeout.toNanos();
        try {
            Map<String, Object> body = requestBody(request);
            body.put("nonce", nonce(request, deadlineNanos));
            byte[] encodedRequest = StrictJson.canonical(body).getBytes(StandardCharsets.UTF_8);
            try {
                try (Response response = transport.post(decisionEndpoint, encodedRequest,
                        remaining(deadlineNanos))) {
                    byte[] encoded = response.body();
                    try {
                        remaining(deadlineNanos);
                        if (encoded.length > 128 * 1024 || response.status() != 200
                                || !"application/json".equals(response.contentType())) {
                            return failClosed(request,
                                    "RISK_SERVICE_HTTP_" + safeStatus(response.status()));
                        }
                        return decode(request, StrictJson.object(strictUtf8(encoded)));
                    } finally {
                        java.util.Arrays.fill(encoded, (byte) 0);
                    }
                }
            } finally {
                java.util.Arrays.fill(encodedRequest, (byte) 0);
            }
        } catch (RuntimeException failure) {
            return failClosed(request, "RISK_SERVICE_UNAVAILABLE");
        }
    }

    private String nonce(RiskEvaluationRequest request, long deadlineNanos) {
        Map<String, Object> binding = Map.of("tenantId", request.tenantId(),
                "projectId", request.projectId(), "requestId", request.requestId(),
                "requestDigest", request.requestDigest());
        byte[] encodedRequest = StrictJson.canonical(binding).getBytes(StandardCharsets.UTF_8);
        try {
            try (Response response = transport.post(nonceEndpoint, encodedRequest,
                    remaining(deadlineNanos))) {
                byte[] encoded = response.body();
                try {
                    if (encoded.length > 128 * 1024 || response.status() != 201
                            || !"application/json".equals(response.contentType())) {
                        throw new IllegalStateException("risk nonce service unavailable");
                    }
                    Map<String, Object> document = StrictJson.object(strictUtf8(encoded));
                    if (!NONCE_FIELDS.equals(document.keySet())) {
                        throw new SecurityException("risk nonce response schema invalid");
                    }
                    String value = string(document, "nonce");
                    Instant expiry = Instant.parse(string(document, "expiresAt"));
                    Instant now = clock.instant();
                    if (!value.matches("[A-Za-z0-9_-]{43}") || !expiry.isAfter(now)
                            || expiry.isAfter(now.plus(Duration.ofMinutes(2)))) {
                        throw new SecurityException("risk nonce response validity invalid");
                    }
                    return value;
                } finally {
                    java.util.Arrays.fill(encoded, (byte) 0);
                }
            }
        } finally {
            java.util.Arrays.fill(encodedRequest, (byte) 0);
        }
    }

    private RiskDecision decode(RiskEvaluationRequest request, Map<String, Object> document) {
        if (!RESPONSE_FIELDS.equals(document.keySet())) {
            return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
        }
        if (!request.tenantId().equals(string(document, "tenantId"))
                || !request.projectId().equals(string(document, "projectId"))
                || !request.requestId().equals(string(document, "requestId"))
                || !request.requestDigest().equals(digest(document, "requestDigest"))
                || !request.operation().name().equals(string(document, "operation"))
                || !request.subjectDigest().equals(digest(document, "subjectDigest"))) {
            return failClosed(request, "RISK_DECISION_BINDING_MISMATCH");
        }
        Object rawReasons = document.get("reasonCodes");
        if (!(rawReasons instanceof List<?> values) || values.isEmpty() || values.size() > 64) {
            return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
        }
        List<String> reasons = new ArrayList<>();
        for (Object value : values) {
            if (!(value instanceof String reason) || !reason.matches("[A-Z][A-Z0-9_]{2,127}")) {
                return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
            }
            reasons.add(reason);
        }
        Object rawDegraded = document.get("degraded");
        if (!(rawDegraded instanceof Boolean degraded)) {
            return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
        }
        Instant decidedAt = Instant.parse(string(document, "decidedAt"));
        Instant now = clock.instant();
        if (decidedAt.isAfter(now.plusSeconds(30)) || decidedAt.isBefore(now.minusSeconds(300))) {
            return failClosed(request, "RISK_DECISION_STALE");
        }
        return new RiskDecision(digest(document, "decisionId"), request.tenantId(),
                request.projectId(), request.requestId(), request.requestDigest(),
                request.operation(), request.subjectDigest(),
                RiskAction.valueOf(string(document, "action")), reasons,
                string(document, "ruleSetVersion"), digest(document, "ruleSetDigest"),
                string(document, "signalVersion"), digest(document, "signalDigest"),
                string(document, "modelVersion"), digest(document, "modelDigest"), degraded,
                decidedAt);
    }

    private RiskDecision failClosed(RiskEvaluationRequest request, String reason) {
        String unavailable = sha256("risk-service-unavailable");
        String id = sha256(request.tenantId() + "\n" + request.projectId() + "\n"
                + request.requestId() + "\n" + request.requestDigest() + "\n" + reason);
        return new RiskDecision(id, request.tenantId(), request.projectId(), request.requestId(),
                request.requestDigest(), request.operation(), request.subjectDigest(),
                RiskAction.REVIEW, List.of(reason), "unavailable", unavailable, "unavailable",
                unavailable, "unavailable", unavailable, true, clock.instant());
    }

    private static Map<String, Object> requestBody(RiskEvaluationRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tenantId", request.tenantId());
        body.put("projectId", request.projectId());
        body.put("requestId", request.requestId());
        body.put("requestDigest", request.requestDigest());
        body.put("operation", request.operation().name());
        body.put("subjectId", request.subjectId());
        body.put("amountMinor", request.amountMinor());
        body.put("currency", request.currency());
        body.put("occurredAt", request.occurredAt().toString());
        body.put("attributes", request.attributes());
        return body;
    }

    private static Transport transport(SSLContext context, Duration timeout) {
        StrictHttpsTransport client = new StrictHttpsTransport(
                Objects.requireNonNull(context, "mutualTlsContext"), timeout, 128 * 1024);
        return new Transport() {
            @Override
            public Response post(URI endpoint, byte[] body) {
                return post(endpoint, body, timeout);
            }

            @Override
            public Response post(URI endpoint, byte[] body, Duration remainingTimeout) {
                try (StrictHttpsTransport.Response response = client.post(endpoint, body,
                        Map.of(), remainingTimeout)) {
                    byte[] encoded = response.body();
                    try {
                        return new Response(response.status(), response.contentType(), encoded);
                    } finally {
                        java.util.Arrays.fill(encoded, (byte) 0);
                    }
                }
            }
        };
    }

    private Duration remaining(long deadlineNanos) {
        long value = deadlineNanos - monotonicNanos.getAsLong();
        if (value <= 0) {
            throw new IllegalStateException("risk evaluation deadline exhausted");
        }
        return Duration.ofNanos(value);
    }

    private static URI decisionEndpoint(URI endpoint) {
        StrictHttpsTransport.exactHttps(endpoint);
        if (!"/v1/risk/decisions".equals(endpoint.getRawPath())) {
            throw new IllegalArgumentException("risk endpoint must be exact /v1/risk/decisions HTTPS");
        }
        return endpoint;
    }

    private static URI sibling(URI endpoint, String path) {
        try {
            return new URI("https", null, endpoint.getHost(), endpoint.getPort(), path, null, null);
        } catch (java.net.URISyntaxException impossible) {
            throw new IllegalArgumentException("risk endpoint origin is invalid", impossible);
        }
    }

    private static String string(Map<String, Object> document, String key) {
        Object value = document.get(key);
        if (!(value instanceof String text) || text.isBlank() || text.length() > 512) {
            throw new IllegalArgumentException("risk response field invalid: " + key);
        }
        return text;
    }

    private static String digest(Map<String, Object> document, String key) {
        String value = string(document, key);
        if (!value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid digest");
        return value;
    }

    private static String strictUtf8(byte[] encoded) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString();
        } catch (CharacterCodingException invalid) {
            throw new SecurityException("risk response is not strict UTF-8", invalid);
        }
    }

    private static int safeStatus(int value) { return value >= 100 && value <= 599 ? value : 599; }

    private static String sha256(String value) {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(encoded));
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("SHA-256 unavailable", failure);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }
}
