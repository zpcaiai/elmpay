package com.elmpay.risk.runtime;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.RiskRule;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsExchange;
import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.LongSupplier;

/** Bounded mTLS HTTP boundary for decision and four-eyes control operations. */
public final class RiskHttpApi implements HttpHandler {
    private static final int MAX_BODY = 128 * 1024;
    private static final int MAX_HEADERS = 32;
    private static final int MAX_HEADER_BYTES = 16 * 1024;
    private static final long REQUEST_DEADLINE_NANOS = Duration.ofSeconds(5).toNanos();
    private static final Set<String> FORBIDDEN_IDENTITY_HEADERS = Set.of("forwarded",
            "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-client-cert",
            "x-ssl-client-cert", "x-spiffe-id", "authorization", "proxy-authorization",
            "transfer-encoding", "expect", "te", "trailer", "upgrade");
    private final RiskDecisionService decisions;
    private final JdbcRiskControlPlane controls;
    private final RiskCallerPolicy callers;
    private final Clock clock;
    private final LongSupplier monotonicNanos;

    public RiskHttpApi(RiskDecisionService decisions, JdbcRiskControlPlane controls,
            RiskCallerPolicy callers, Clock clock) {
        this(decisions, controls, callers, clock, System::nanoTime);
    }

    RiskHttpApi(RiskDecisionService decisions, JdbcRiskControlPlane controls,
            RiskCallerPolicy callers, Clock clock, LongSupplier monotonicNanos) {
        this.decisions = Objects.requireNonNull(decisions, "decisions");
        this.controls = Objects.requireNonNull(controls, "controls");
        this.callers = Objects.requireNonNull(callers, "callers");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.monotonicNanos = Objects.requireNonNull(monotonicNanos, "monotonicNanos");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        long requestStarted = monotonicNanos.getAsLong();
        try {
            if (!(exchange instanceof HttpsExchange secure)) {
                send(exchange, 400, Map.of("code", "TLS_REQUIRED"));
                return;
            }
            URI requestUri = exchange.getRequestURI();
            if (requestUri.isAbsolute() || requestUri.getRawAuthority() != null
                    || requestUri.getRawQuery() != null || requestUri.getRawFragment() != null
                    || requestUri.getRawPath() == null
                    || !requestUri.getRawPath().equals(requestUri.getPath())
                    || requestUri.getRawPath().contains("//")
                    || !requestUri.normalize().equals(requestUri)) {
                send(exchange, 400, Map.of("code", "INVALID_REQUEST_TARGET"));
                return;
            }
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "POST");
                send(exchange, 405, Map.of("code", "METHOD_NOT_ALLOWED"));
                return;
            }
            long contentLength = validateHeaders(exchange);
            String caller = spiffe(secure, clock.instant());
            byte[] raw = exchange.getRequestBody().readNBytes(MAX_BODY + 1);
            try {
                if (raw.length > MAX_BODY
                        || requestBudgetExceeded(monotonicNanos, requestStarted)) {
                    send(exchange, 413, Map.of("code", "REQUEST_BOUND_EXCEEDED"));
                    return;
                }
                if (raw.length != contentLength) {
                    send(exchange, 400, Map.of("code", "CONTENT_LENGTH_MISMATCH"));
                    return;
                }
                Map<String, Object> body = StrictJson.object(strictUtf8(raw));
                Route route = route(requestUri.getPath());
                callers.require(caller, route.capability(), text(body, "tenantId"),
                        text(body, "projectId"));
                Object result = route.execute(body, caller);
                send(exchange, route.created() ? 201 : 200, result);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (JdbcRiskDecisionService.RejectedRequest rejected) {
            int status = rejected.code().contains("CONFLICT") ? 409 : 401;
            send(exchange, status, Map.of("code", rejected.code()));
        } catch (SecurityException forbidden) {
            send(exchange, 403, Map.of("code", "FORBIDDEN"));
        } catch (IllegalArgumentException invalid) {
            send(exchange, 400, Map.of("code", "INVALID_REQUEST"));
        } catch (IllegalStateException unavailable) {
            send(exchange, 503, Map.of("code", "DEPENDENCY_UNAVAILABLE"));
        } finally {
            exchange.close();
        }
    }

    static boolean requestBudgetExceeded(LongSupplier ticker, long startedNanos) {
        return Objects.requireNonNull(ticker, "ticker").getAsLong() - startedNanos
                >= REQUEST_DEADLINE_NANOS;
    }

    private Route route(String path) {
        return switch (path) {
            case "/v1/risk/nonces" -> new Route("risk.evaluate", true,
                    (body, caller) -> nonce(body, caller));
            case "/v1/risk/decisions" -> new Route("risk.evaluate", false,
                    (body, caller) -> decision(body, caller));
            case "/v1/risk/rule-sets/propose" -> new Route("rules.propose", true,
                    (body, caller) -> proposeRules(body, caller));
            case "/v1/risk/rule-sets/approve" -> new Route("rules.approve", false,
                    (body, caller) -> approveRules(body, caller));
            case "/v1/risk/rule-sets/activate" -> new Route("rules.activate", false,
                    (body, caller) -> activateRules(body, caller));
            case "/v1/risk/operations/propose" -> new Route("operations.propose", true,
                    (body, caller) -> proposeOperation(body, caller));
            case "/v1/risk/operations/approve" -> new Route("operations.approve", false,
                    (body, caller) -> approveOperation(body, caller));
            default -> throw new IllegalArgumentException("unknown risk route");
        };
    }

    private Object nonce(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "requestId", "requestDigest"));
        var challenge = decisions.issueNonce(new RiskDecisionService.NonceBinding(
                text(body, "tenantId"), text(body, "projectId"), text(body, "requestId"),
                text(body, "requestDigest")), caller);
        return Map.of("nonce", challenge.nonce(), "expiresAt", challenge.expiresAt().toString());
    }

    private Object decision(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "requestId", "requestDigest", "operation",
                "subjectId", "amountMinor", "currency", "occurredAt", "attributes", "nonce"));
        Map<String, String> attributes = stringMap(body.get("attributes"));
        RiskEvaluationRequest request = new RiskEvaluationRequest(text(body, "tenantId"),
                text(body, "projectId"), text(body, "requestId"),
                RiskOperation.valueOf(text(body, "operation")), text(body, "subjectId"),
                integer(body, "amountMinor"), text(body, "currency"),
                Instant.parse(text(body, "occurredAt")), attributes);
        if (!request.requestDigest().equals(text(body, "requestDigest"))) {
            throw new SecurityException("request digest mismatch");
        }
        return decisionDocument(decisions.decide(request, text(body, "nonce"), caller));
    }

    private Object proposeRules(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "version", "activatedAt", "expiresAt",
                "rules", "reasonCode", "ticketDigest"));
        Object rawRules = body.get("rules");
        if (!(rawRules instanceof List<?> values) || values.isEmpty() || values.size() > 256) {
            throw new IllegalArgumentException("rules schema invalid");
        }
        List<RiskRule> rules = new ArrayList<>();
        for (Object value : values) rules.add(rule(value));
        return proposal(controls.proposeRuleSet(text(body, "tenantId"), text(body, "projectId"),
                text(body, "version"), Instant.parse(text(body, "activatedAt")),
                Instant.parse(text(body, "expiresAt")), rules, text(body, "reasonCode"),
                text(body, "ticketDigest"), caller));
    }

    private Object approveRules(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "proposalId", "expectedVersion"));
        return proposal(controls.approveRuleSet(text(body, "tenantId"), text(body, "projectId"),
                UUID.fromString(text(body, "proposalId")), integer(body, "expectedVersion"), caller));
    }

    private Object activateRules(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "proposalId", "expectedVersion"));
        return proposal(controls.activateRuleSet(text(body, "tenantId"), text(body, "projectId"),
                UUID.fromString(text(body, "proposalId")), integer(body, "expectedVersion"), caller));
    }

    private Object proposeOperation(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "kind", "subjectDigest", "reasonCode",
                "ticketDigest"));
        return proposal(controls.proposeOperation(text(body, "tenantId"), text(body, "projectId"),
                JdbcRiskControlPlane.OperationKind.valueOf(text(body, "kind")),
                text(body, "subjectDigest"), text(body, "reasonCode"),
                text(body, "ticketDigest"), caller));
    }

    private Object approveOperation(Map<String, Object> body, String caller) {
        exact(body, Set.of("tenantId", "projectId", "operationId", "expectedVersion"));
        return proposal(controls.approveAndApplyOperation(text(body, "tenantId"),
                text(body, "projectId"), UUID.fromString(text(body, "operationId")),
                integer(body, "expectedVersion"), caller));
    }

    private static Map<String, Object> proposal(JdbcRiskControlPlane.Proposal value) {
        return Map.of("id", value.id().toString(), "version", value.version(),
                "state", value.state(), "contentDigest", value.contentDigest());
    }

    private static RiskRule rule(Object raw) {
        if (!(raw instanceof Map<?, ?> value)) throw new IllegalArgumentException("rule invalid");
        Set<String> fields = Set.of("id", "version", "priority", "signal", "operator",
                "threshold", "action", "reasonCode");
        if (!fields.equals(value.keySet())) throw new IllegalArgumentException("rule schema invalid");
        return new RiskRule(text(value, "id"), text(value, "version"),
                Math.toIntExact(integer(value, "priority")), text(value, "signal"),
                RiskRule.Operator.valueOf(text(value, "operator")),
                new BigDecimal(text(value, "threshold")),
                com.elmpay.risk.RiskAction.valueOf(text(value, "action")),
                text(value, "reasonCode"));
    }

    public static Map<String, Object> decisionDocument(RiskDecision value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("decisionId", value.decisionId());
        result.put("tenantId", value.tenantId());
        result.put("projectId", value.projectId());
        result.put("requestId", value.requestId());
        result.put("requestDigest", value.requestDigest());
        result.put("operation", value.operation().name());
        result.put("subjectDigest", value.subjectDigest());
        result.put("action", value.action().name());
        result.put("reasonCodes", value.reasonCodes());
        result.put("ruleSetVersion", value.ruleSetVersion());
        result.put("ruleSetDigest", value.ruleSetDigest());
        result.put("signalVersion", value.signalVersion());
        result.put("signalDigest", value.signalDigest());
        result.put("modelVersion", value.modelVersion());
        result.put("modelDigest", value.modelDigest());
        result.put("degraded", value.degraded());
        result.put("decidedAt", value.decidedAt().toString());
        return Map.copyOf(result);
    }

    private static String spiffe(HttpsExchange exchange, Instant now) {
        try {
            var session = exchange.getSSLSession();
            var certificates = session.getPeerCertificates();
            if (certificates.length < 1 || !(certificates[0] instanceof X509Certificate leaf)) {
                throw new SecurityException("client certificate missing");
            }
            return spiffe(leaf, session.getProtocol(), now);
        } catch (javax.net.ssl.SSLPeerUnverifiedException failure) {
            throw new SecurityException("client identity is unavailable", failure);
        }
    }

    static String spiffe(X509Certificate leaf, String protocol, Instant now) {
        Objects.requireNonNull(leaf, "leaf");
        Objects.requireNonNull(now, "now");
        if (!"TLSv1.3".equals(protocol)) {
            throw new SecurityException("client TLS protocol is not TLS 1.3");
        }
        try {
            leaf.checkValidity(Date.from(now));
            List<String> purposes = leaf.getExtendedKeyUsage();
            if (leaf.getBasicConstraints() >= 0 || purposes == null
                    || !purposes.contains("1.3.6.1.5.5.7.3.2")) {
                throw new SecurityException("client certificate purpose is invalid");
            }
            boolean[] keyUsage = leaf.getKeyUsage();
            if (keyUsage == null || keyUsage.length == 0 || !keyUsage[0]) {
                throw new SecurityException("client certificate cannot sign TLS handshakes");
            }
            Collection<List<?>> names = leaf.getSubjectAlternativeNames();
            List<String> identities = new ArrayList<>();
            if (names != null) {
                for (List<?> entry : names) {
                    if (entry.size() == 2 && Integer.valueOf(6).equals(entry.getFirst())) {
                        if (!(entry.get(1) instanceof String rawUri)) {
                            throw new SecurityException("client URI SAN is malformed");
                        }
                        URI uri = URI.create(rawUri);
                        if (!"spiffe".equals(uri.getScheme())
                                || !validTrustDomain(uri.getHost())
                                || uri.getPort() != -1 || uri.getUserInfo() != null
                                || uri.getQuery() != null || uri.getFragment() != null
                                || uri.getRawPath() == null
                                || !uri.getRawPath().equals(uri.getPath())
                                || !uri.normalize().equals(uri)
                                || !uri.getPath().matches(
                                        "/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
                                || !rawUri.equals("spiffe://"
                                        + uri.getHost().toLowerCase(java.util.Locale.ROOT)
                                        + uri.getPath())) {
                            throw new SecurityException("client SPIFFE URI is not canonical");
                        }
                        identities.add(rawUri);
                    }
                }
            }
            if (identities.size() != 1) throw new SecurityException("one SPIFFE URI SAN required");
            return identities.getFirst();
        } catch (java.security.cert.CertificateException | IllegalArgumentException failure) {
            throw new SecurityException("client identity is unavailable", failure);
        }
    }

    private static boolean validTrustDomain(String value) {
        if (value == null || value.isEmpty() || value.length() > 253
                || !value.equals(value.toLowerCase(java.util.Locale.ROOT))) {
            return false;
        }
        for (String label : value.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63
                    || !label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) {
                return false;
            }
        }
        return true;
    }

    private static long validateHeaders(HttpExchange exchange) {
        int count = 0;
        int bytes = 0;
        for (Map.Entry<String, List<String>> entry : exchange.getRequestHeaders().entrySet()) {
            if (!entry.getKey().matches("[A-Za-z0-9-]{1,64}")) {
                throw new IllegalArgumentException("request header name is invalid");
            }
            if (FORBIDDEN_IDENTITY_HEADERS.contains(
                    entry.getKey().toLowerCase(java.util.Locale.ROOT))) {
                throw new IllegalArgumentException("forwarded or ambiguous identity header");
            }
            count += entry.getValue().size();
            bytes += entry.getKey().length();
            for (String value : entry.getValue()) {
                if (value == null || value.length() > 4096
                        || value.codePoints().anyMatch(character -> character < 0x20
                                || character == 0x7f)) {
                    throw new IllegalArgumentException("request header value is invalid");
                }
                bytes += value.length();
            }
        }
        if (count > MAX_HEADERS || bytes > MAX_HEADER_BYTES) {
            throw new IllegalArgumentException("request headers exceed bounds");
        }
        List<String> contentTypes = exchange.getRequestHeaders().get("Content-Type");
        if (contentTypes == null || contentTypes.size() != 1
                || !"application/json".equals(contentTypes.getFirst())) {
            throw new IllegalArgumentException("one exact application/json content type required");
        }
        List<String> lengths = exchange.getRequestHeaders().get("Content-Length");
        if (lengths == null || lengths.size() != 1
                || !lengths.getFirst().matches("(?:0|[1-9][0-9]{0,5})")) {
            throw new IllegalArgumentException("one canonical content length required");
        }
        long length = Long.parseLong(lengths.getFirst());
        if (length < 2 || length > MAX_BODY) {
            throw new IllegalArgumentException("request content length exceeds bounds");
        }
        List<String> hosts = exchange.getRequestHeaders().get("Host");
        if (hosts != null && hosts.size() != 1) {
            throw new IllegalArgumentException("duplicate host header");
        }
        List<String> accepts = exchange.getRequestHeaders().get("Accept");
        if (accepts != null && (accepts.size() != 1
                || !"application/json".equals(accepts.getFirst()))) {
            throw new IllegalArgumentException("accept header is invalid");
        }
        return length;
    }

    private static void send(HttpExchange exchange, int status, Object document) throws IOException {
        byte[] body = StrictJson.canonical(document).getBytes(StandardCharsets.UTF_8);
        try {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    private static void exact(Map<?, ?> body, Set<String> keys) {
        if (!keys.equals(body.keySet())) throw new IllegalArgumentException("request schema invalid");
    }

    private static String strictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(value)).toString();
        } catch (java.nio.charset.CharacterCodingException invalid) {
            throw new IllegalArgumentException("request body is not canonical UTF-8", invalid);
        }
    }

    private static String text(Map<?, ?> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String text) || text.isBlank() || text.length() > 512) {
            throw new IllegalArgumentException("request field invalid: " + key);
        }
        return text;
    }

    private static long integer(Map<?, ?> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof Long number)) throw new IllegalArgumentException("integer invalid");
        return number;
    }

    private static Map<String, String> stringMap(Object raw) {
        if (!(raw instanceof Map<?, ?> values) || values.size() > 32) {
            throw new IllegalArgumentException("attributes invalid");
        }
        Map<String, String> result = new LinkedHashMap<>();
        values.forEach((key, value) -> {
            if (!(key instanceof String textKey) || !(value instanceof String textValue)
                    || !textKey.matches("[A-Za-z][A-Za-z0-9_.-]{0,63}")
                    || textValue.isEmpty() || textValue.length() > 256
                    || textValue.codePoints().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("attributes invalid");
            }
            result.put(textKey, textValue);
        });
        return Map.copyOf(result);
    }

    private record Route(String capability, boolean created, Executor executor) {
        Object execute(Map<String, Object> body, String caller) { return executor.run(body, caller); }
    }
    @FunctionalInterface private interface Executor {
        Object run(Map<String, Object> body, String caller);
    }
}
