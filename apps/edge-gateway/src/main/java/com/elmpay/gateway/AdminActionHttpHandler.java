package com.elmpay.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Strict-mTLS HTTP adapter for governed internal admin actions and safe diagnostics. */
public final class AdminActionHttpHandler implements HttpHandler {
    public static final String ACTIONS_PATH = "/internal/admin/actions";
    public static final String DIAGNOSTICS_PATH = "/internal/admin/diagnostics";
    public static final String READY_PATH = "/health/ready";
    private static final int MAXIMUM_BODY_BYTES = 16_384;
    private static final int MAXIMUM_HEADER_BYTES = 16_384;
    private static final int MAXIMUM_HEADER_VALUES = 64;
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern UUID_TEXT = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    private static final Pattern SERVICE = Pattern.compile("[a-z][a-z0-9-]{1,62}");

    private final JdbcAdminActionService service;
    private final AdminActionPeerVerifier peerVerifier;

    public AdminActionHttpHandler(AdminActionRuntimeFactory.Runtime runtime) {
        this.service = java.util.Objects.requireNonNull(runtime, "runtime").service();
        this.peerVerifier = runtime.peerVerifier();
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            requireCanonicalRequest(exchange);
            peerVerifier.verify(exchange);
            route(exchange);
        } catch (AdminActionException failure) {
            int status = switch (failure.code()) {
                case "ADMIN_PEER_UNAUTHENTICATED" -> 401;
                case "DIAGNOSTIC_NOT_FOUND" -> 404;
                case "IDEMPOTENCY_CONFLICT", "STALE_DISPATCH_FENCE" -> 409;
                case "ADMIN_ACTION_DATABASE_UNAVAILABLE" -> 503;
                default -> 422;
            };
            problem(exchange, status, failure.code());
        } catch (IllegalArgumentException failure) {
            problem(exchange, 400, "INVALID_ADMIN_ACTION_REQUEST");
        } catch (RuntimeException failure) {
            problem(exchange, 500, "ADMIN_ACTION_FAILED");
        } finally {
            exchange.close();
        }
    }

    private void route(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if (READY_PATH.equals(path)) {
            if (!"GET".equals(exchange.getRequestMethod())
                    || exchange.getRequestURI().getRawQuery() != null) {
                problem(exchange, 405, "METHOD_NOT_ALLOWED");
                return;
            }
            boolean ready = service.ready();
            respond(exchange, ready ? 200 : 503,
                    Map.of("service", "admin-action-api",
                            "status", ready ? "UP" : "NOT_READY"));
            return;
        }
        if ((ACTIONS_PATH + "/capabilities").equals(path)) {
            if (!"GET".equals(exchange.getRequestMethod())
                    || exchange.getRequestURI().getRawQuery() != null) {
                problem(exchange, 405, "METHOD_NOT_ALLOWED");
                return;
            }
            respond(exchange, 200, Map.of("schemaVersion", 2,
                    "dispatchContract", "elmpay.admin-action.v2",
                    "receiptContract", "elmpay.admin-action-receipt.v1",
                    "actions", List.of("CASE_CLOSE", "LIST_CHANGE", "REFUND_OVERRIDE",
                            "ROLLOUT_APPROVAL")));
            return;
        }
        if ((ACTIONS_PATH + "/dispatches").equals(path)) {
            dispatch(exchange);
            return;
        }
        String receiptPrefix = ACTIONS_PATH + "/receipts/";
        if (path.startsWith(receiptPrefix)) {
            receipt(exchange, path.substring(receiptPrefix.length()));
            return;
        }
        if (DIAGNOSTICS_PATH.equals(path)) {
            diagnostic(exchange);
            return;
        }
        problem(exchange, 404, "NOT_FOUND");
    }

    private void dispatch(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())
                || exchange.getRequestURI().getRawQuery() != null) {
            problem(exchange, 405, "METHOD_NOT_ALLOWED");
            return;
        }
        AdminActionEnvelope command = AdminActionEnvelope.from(
                StrictJsonHttpRequest.body(exchange, MAXIMUM_BODY_BYTES,
                        AdminActionEnvelope.fields()));
        String idempotency = singleHeader(exchange, "Idempotency-Key");
        if (!command.idempotencyKey().equals(idempotency)
                || !command.tenantId().equals(tenantHeader(exchange))) {
            throw new IllegalArgumentException("idempotency header is not command-bound");
        }
        JdbcAdminActionService.DispatchResult result = service.dispatch(command);
        if (result.receipt().isPresent()) {
            respond(exchange, 200, result.receipt().orElseThrow().asJson());
        } else if (result.state() == com.elmpay.admin.AdminDomainCommandQueue.State.BLOCKED) {
            problem(exchange, 409, "ADMIN_DOMAIN_COMMAND_BLOCKED");
        } else {
            respond(exchange, 202, result.pendingJson());
        }
    }

    private void receipt(HttpExchange exchange, String idempotencyKey) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())
                || exchange.getRequestURI().getRawQuery() != null
                || !DIGEST.matcher(idempotencyKey).matches()) {
            problem(exchange, 400, "INVALID_RECEIPT_REQUEST");
            return;
        }
        UUID tenantId = tenantHeader(exchange);
        JdbcAdminActionService.LookupResult lookup = service.lookup(tenantId, idempotencyKey);
        if (lookup.receipt().isPresent()) {
            respond(exchange, 200, lookup.receipt().orElseThrow().asJson());
            return;
        }
        if (lookup.state().isEmpty()) {
            problem(exchange, 404, "RECEIPT_NOT_FOUND");
            return;
        }
        if (lookup.state().orElseThrow()
                == com.elmpay.admin.AdminDomainCommandQueue.State.BLOCKED) {
            problem(exchange, 409, "ADMIN_DOMAIN_COMMAND_BLOCKED");
            return;
        }
        respond(exchange, 202, Map.of("schemaVersion", 1,
                "status", lookup.state().orElseThrow().name()));
    }

    private void diagnostic(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            problem(exchange, 405, "METHOD_NOT_ALLOWED");
            return;
        }
        Map<String, String> query = query(exchange.getRequestURI().getRawQuery());
        if (!query.keySet().equals(Set.of("tenantId", "service"))
                || !UUID_TEXT.matcher(query.get("tenantId")).matches()
                || !SERVICE.matcher(query.get("service")).matches()) {
            throw new IllegalArgumentException("diagnostic query is invalid");
        }
        UUID tenantId = tenantHeader(exchange);
        if (!tenantId.toString().equals(query.get("tenantId"))) {
            throw new AdminActionException("DIAGNOSTIC_BINDING_INVALID",
                    "diagnostic tenant selector does not match its scope header");
        }
        String operatorDigest = singleHeader(exchange,
                "X-Elmpay-Operator-Subject-Digest");
        if (operatorDigest == null || !DIGEST.matcher(operatorDigest).matches()) {
            throw new AdminActionException("DIAGNOSTIC_BINDING_INVALID",
                    "diagnostic operator digest is required");
        }
        respond(exchange, 200,
                service.diagnostic(tenantId, query.get("service"), operatorDigest));
    }

    private static UUID tenantHeader(HttpExchange exchange) {
        String tenant = singleHeader(exchange, "X-Elmpay-Tenant-Id");
        if (tenant == null || !UUID_TEXT.matcher(tenant).matches()) {
            throw new IllegalArgumentException("tenant scope header is invalid");
        }
        return UUID.fromString(tenant);
    }

    private static void requireCanonicalRequest(HttpExchange exchange) {
        StrictJsonHttpRequest.validateEnvelope(exchange);
        URI request = exchange.getRequestURI();
        String rawPath = request.getRawPath();
        if (request.isAbsolute() || request.getRawAuthority() != null
                || request.getRawFragment() != null || rawPath == null || rawPath.isEmpty()
                || rawPath.indexOf('%') >= 0 || !rawPath.equals(request.getPath())
                || !rawPath.equals(request.normalize().getRawPath()) || rawPath.contains("//")
                || (rawPath.length() > 1 && rawPath.endsWith("/"))) {
            throw new IllegalArgumentException("request target is not canonical origin-form");
        }
        int values = 0;
        int bytes = 0;
        for (Map.Entry<String, List<String>> header : exchange.getRequestHeaders().entrySet()) {
            bytes += header.getKey().getBytes(StandardCharsets.UTF_8).length;
            values += header.getValue().size();
            for (String value : header.getValue()) {
                bytes += value.getBytes(StandardCharsets.UTF_8).length;
            }
            if (values > MAXIMUM_HEADER_VALUES || bytes > MAXIMUM_HEADER_BYTES) {
                throw new IllegalArgumentException("request headers exceed their bound");
            }
        }
    }

    private static String singleHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null || values.size() != 1 || values.get(0).isBlank()) {
            return null;
        }
        return values.get(0);
    }

    static Map<String, String> query(String rawQuery) {
        if (rawQuery == null) {
            return Map.of();
        }
        if (rawQuery.isEmpty() || rawQuery.length() > 256
                || rawQuery.indexOf('%') >= 0 || rawQuery.indexOf('+') >= 0
                || rawQuery.chars().anyMatch(character -> character < 0x20
                        || character == 0x7f)) {
            throw new IllegalArgumentException("query is malformed");
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (String part : rawQuery.split("&", -1)) {
            String[] pair = part.split("=", -1);
            if (pair.length != 2
                    || !pair[0].matches("(?:tenantId|service)")
                    || !pair[1].matches("[A-Za-z0-9._:-]{1,128}")) {
                throw new IllegalArgumentException("query is malformed");
            }
            if (result.putIfAbsent(pair[0], pair[1]) != null) {
                throw new IllegalArgumentException("query key is duplicated");
            }
        }
        return Map.copyOf(result);
    }

    private static void problem(HttpExchange exchange, int status, String code)
            throws IOException {
        respond(exchange, status,
                Map.of("type", "about:blank", "status", status, "code", code));
    }

    private static void respond(HttpExchange exchange, int status, Map<String, ?> value)
            throws IOException {
        byte[] body = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("Pragma", "no-cache");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }
}
