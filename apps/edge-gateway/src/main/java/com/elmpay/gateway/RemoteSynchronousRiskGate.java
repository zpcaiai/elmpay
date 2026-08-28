package com.elmpay.gateway;

import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.SynchronousRiskGate;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Authenticated finite-time adapter to the durable Python/Postgres risk decision runtime. */
final class RemoteSynchronousRiskGate implements SynchronousRiskGate {
    private static final int MAX_RESPONSE_BYTES = 65_536;
    private static final Set<String> RESPONSE_FIELDS = Set.of("decisionId", "tenantId",
            "requestId", "operation", "subjectDigest", "action", "reasonCodes",
            "ruleSetVersion", "ruleSetDigest", "signalVersion", "modelVersion", "degraded",
            "decidedAt");
    private final URI endpoint;
    private final byte[] hmacSecret;
    private final Duration timeout;
    private final Clock clock;
    private final HttpClient client;

    RemoteSynchronousRiskGate(URI endpoint, byte[] hmacSecret, Duration timeout,
            Clock clock, boolean allowLoopbackHttp) {
        this(endpoint, hmacSecret, timeout, clock, allowLoopbackHttp,
                HttpClient.newBuilder().connectTimeout(timeout)
                        .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    RemoteSynchronousRiskGate(URI endpoint, byte[] hmacSecret, Duration timeout,
            Clock clock, boolean allowLoopbackHttp, HttpClient client) {
        this.endpoint = validateEndpoint(endpoint, allowLoopbackHttp);
        this.hmacSecret = Objects.requireNonNull(hmacSecret, "hmacSecret").clone();
        if (this.hmacSecret.length < 32) {
            throw new IllegalArgumentException("risk HMAC secret must contain at least 32 bytes");
        }
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new IllegalArgumentException("risk timeout must be within 1ms..5s");
        }
        this.clock = Objects.requireNonNull(clock, "clock");
        this.client = Objects.requireNonNull(client, "client");
    }

    @Override
    public RiskDecision evaluate(RiskEvaluationRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            String body = Json.stringify(body(request));
            String timestamp = Long.toString(clock.instant().getEpochSecond());
            String nonce = UUID.randomUUID().toString();
            String signature = sign(timestamp + "\n" + nonce + "\n" + sha256(body));
            HttpRequest message = HttpRequest.newBuilder(endpoint).timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("X-Elmpay-Risk-Timestamp", timestamp)
                    .header("X-Elmpay-Risk-Nonce", nonce)
                    .header("X-Elmpay-Risk-Signature", signature)
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            HttpResponse<String> response = client.send(message,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                return failClosed(request, "RISK_SERVICE_HTTP_" + response.statusCode());
            }
            if (response.body().getBytes(StandardCharsets.UTF_8).length > MAX_RESPONSE_BYTES) {
                return failClosed(request, "RISK_SERVICE_RESPONSE_TOO_LARGE");
            }
            return decode(request, Json.object(response.body()));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return failClosed(request, "RISK_SERVICE_INTERRUPTED");
        } catch (IOException | RuntimeException exception) {
            return failClosed(request, "RISK_SERVICE_UNAVAILABLE");
        }
    }

    private RiskDecision decode(RiskEvaluationRequest request, Map<String, Object> document) {
        if (!RESPONSE_FIELDS.equals(document.keySet())) {
            return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
        }
        String tenant = string(document, "tenantId");
        String requestId = string(document, "requestId");
        String operation = string(document, "operation");
        if (!request.tenantId().equals(tenant) || !request.requestId().equals(requestId)
                || !request.operation().name().equals(operation)) {
            return failClosed(request, "RISK_DECISION_BINDING_MISMATCH");
        }
        String decisionId = digest(document, "decisionId");
        digest(document, "subjectDigest");
        RiskAction action = RiskAction.valueOf(string(document, "action"));
        Object rawReasons = document.get("reasonCodes");
        if (!(rawReasons instanceof List<?> list) || list.isEmpty() || list.size() > 64) {
            return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
        }
        List<String> reasons = new ArrayList<>();
        for (Object rawReason : list) {
            if (!(rawReason instanceof String reason)
                    || !reason.matches("[A-Z][A-Z0-9_]{2,127}")) {
                return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
            }
            reasons.add(reason);
        }
        Object rawDegraded = document.get("degraded");
        if (!(rawDegraded instanceof Boolean degraded)) {
            return failClosed(request, "RISK_SERVICE_RESPONSE_SCHEMA_INVALID");
        }
        return new RiskDecision(decisionId, tenant, requestId, action, reasons,
                string(document, "ruleSetVersion"), digest(document, "ruleSetDigest"),
                string(document, "signalVersion"), string(document, "modelVersion"), degraded,
                Instant.parse(string(document, "decidedAt")));
    }

    private RiskDecision failClosed(RiskEvaluationRequest request, String reason) {
        return new RiskDecision(sha256(request.tenantId() + "\n" + request.requestId()
                        + "\n" + reason), request.tenantId(), request.requestId(),
                RiskAction.REVIEW, List.of(reason), "unavailable", sha256("unavailable"),
                "unavailable", "unavailable", true, clock.instant());
    }

    private static Map<String, Object> body(RiskEvaluationRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tenantId", request.tenantId());
        body.put("requestId", request.requestId());
        body.put("operation", request.operation().name());
        body.put("subjectId", request.subjectId());
        body.put("amountMinor", request.amountMinor());
        body.put("currency", request.currency());
        body.put("occurredAt", request.occurredAt());
        body.put("attributes", request.attributes());
        return Map.copyOf(body);
    }

    private String sign(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacSecret, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", exception);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private static URI validateEndpoint(URI endpoint, boolean allowLoopbackHttp) {
        Objects.requireNonNull(endpoint, "endpoint");
        boolean secure = "https".equalsIgnoreCase(endpoint.getScheme());
        boolean loopback = "http".equalsIgnoreCase(endpoint.getScheme()) && allowLoopbackHttp
                && Set.of("127.0.0.1", "localhost", "::1").contains(endpoint.getHost());
        if ((!secure && !loopback) || endpoint.getUserInfo() != null
                || endpoint.getFragment() != null || endpoint.getQuery() != null
                || !"/v1/risk/decisions".equals(endpoint.getPath())) {
            throw new IllegalArgumentException(
                    "risk endpoint must be HTTPS (or explicit local loopback) /v1/risk/decisions");
        }
        return endpoint;
    }

    private static String string(Map<String, Object> document, String key) {
        Object value = document.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("risk response field is invalid: " + key);
        }
        return text;
    }

    private static String digest(Map<String, Object> document, String key) {
        String value = string(document, key);
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("risk response digest is invalid: " + key);
        }
        return value;
    }
}
