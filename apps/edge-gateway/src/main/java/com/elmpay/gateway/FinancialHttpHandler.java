package com.elmpay.gateway;

import com.elmpay.reconciliation.FinancialOperationsService;
import com.elmpay.reconciliation.StatementIngestionService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Authenticated B75-B79 statement, settlement, exception and signed-report endpoint. */
public final class FinancialHttpHandler implements HttpHandler {
    private static final int MAX_BODY_BYTES = 14_000_000;
    private final ApiKeyAuthenticator authenticator;
    private final Optional<FinancialOperationsService> financial;

    public FinancialHttpHandler(ApiKeyAuthenticator authenticator,
            Optional<FinancialOperationsService> financial) {
        this.authenticator = java.util.Objects.requireNonNull(authenticator, "authenticator");
        this.financial = java.util.Objects.requireNonNull(financial, "financial");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = exchange.getRequestHeaders().getFirst("X-Request-Id");
        try {
            if (!validRequestId(requestId) || !validTraceparent(
                    exchange.getRequestHeaders().getFirst("traceparent"))) {
                error(exchange, 400, "invalid_request",
                        "X-Request-Id and a valid traceparent are required", safe(requestId));
                return;
            }
            ApiPrincipal principal = authenticator.authenticate(exchange.getRequestHeaders())
                    .orElse(null);
            if (principal == null) {
                error(exchange, 401, "unauthenticated", "valid bearer credentials are required",
                        requestId);
                return;
            }
            requireProject(exchange, principal);
            FinancialOperationsService service = financial.orElseThrow(() ->
                    new IllegalStateException("financial runtime is not configured"));
            route(exchange, principal, service, requestId);
        } catch (AccessDeniedException denied) {
            error(exchange, 403, "forbidden", denied.getMessage(), safe(requestId));
        } catch (SecurityException denied) {
            error(exchange, 403, "four_eyes_required", denied.getMessage(), safe(requestId));
        } catch (IllegalArgumentException invalid) {
            error(exchange, 400, "invalid_request", "request does not satisfy the API contract",
                    safe(requestId));
        } catch (IllegalStateException unavailable) {
            error(exchange, 503, "financial_runtime_unavailable",
                    "financial operation could not be completed", safe(requestId));
        } catch (RuntimeException failure) {
            error(exchange, 500, "internal_error", "request could not be completed",
                    safe(requestId));
        } finally {
            exchange.close();
        }
    }

    private static void route(HttpExchange exchange, ApiPrincipal principal,
            FinancialOperationsService service, String requestId) throws IOException {
        String path = exchange.getRequestURI().getPath();
        Map<String, String> query = query(exchange.getRequestURI().getRawQuery());
        if ("POST".equals(exchange.getRequestMethod())
                && "/v1/finance/statements".equals(path)) {
            requireScope(principal, ApiPrincipal.FINANCIAL_WRITE);
            Map<String, Object> body = body(exchange, Set.of("kind", "source", "parser_version",
                    "content_base64"));
            byte[] raw;
            try {
                raw = Base64.getDecoder().decode(string(body, "content_base64"));
            } catch (IllegalArgumentException invalid) {
                throw new IllegalArgumentException("statement body is not base64", invalid);
            }
            StatementIngestionService.Ingested value = service.ingestStatement(
                    principal.tenantId().toString(), StatementIngestionService.Kind.valueOf(
                            string(body, "kind").toUpperCase(java.util.Locale.ROOT)),
                    string(body, "source"), string(body, "parser_version"), raw);
            response(exchange, value.duplicate() ? 200 : 201, Map.of("id", value.id(),
                    "kind", value.kind(), "source", value.source(), "sha256", value.digest(),
                    "parser_version", value.parserVersion(), "row_count", value.rows().size(),
                    "duplicate", value.duplicate()), requestId);
            return;
        }
        if ("GET".equals(exchange.getRequestMethod()) && "/v1/finance/reports".equals(path)) {
            requireScope(principal, ApiPrincipal.FINANCIAL_READ);
            FinancialOperationsService.SignedReport value = service.generateReport(
                    principal.tenantId().toString(), Instant.parse(required(query, "from")),
                    Instant.parse(required(query, "to")));
            Map<String, Object> totals = new LinkedHashMap<>();
            value.report().byCurrency().forEach((currency, total) -> totals.put(currency,
                    Map.of("gmv_minor", total.gmvMinor(), "fee_minor", total.feeMinor(),
                            "refund_minor", total.refundMinor(), "chargeback_minor",
                            total.chargebackMinor(), "settlement_minor", total.settlementMinor(),
                            "exception_minor", total.exceptionMinor(), "net_revenue_minor",
                            total.netRevenueMinor())));
            response(exchange, 200, Map.of("from", value.report().from(), "to",
                    value.report().to(), "by_currency", totals, "source_digest",
                    value.report().sourceDigest(), "signing_key_version",
                    value.report().signingKeyVersion(), "manifest_signature",
                    value.report().manifestSignature(), "object_digest", value.objectDigest()),
                    requestId);
            return;
        }
        if ("GET".equals(exchange.getRequestMethod())
                && "/v1/finance/settlements".equals(path)) {
            requireScope(principal, ApiPrincipal.FINANCIAL_READ);
            List<Map<String, Object>> values = new ArrayList<>();
            service.settlements(principal.tenantId().toString(),
                    Instant.parse(required(query, "from")), Instant.parse(required(query, "to")),
                    limit(query)).forEach(item -> values.add(Map.of("provider_batch_id",
                            item.providerBatchId(), "currency", item.currency(), "gross_minor",
                            item.grossMinor(), "fee_minor", item.feeMinor(), "expected_bank_minor",
                            item.expectedBankMinor(), "expected_arrival", item.expectedArrival(),
                            "provider_status", item.providerStatus())));
            response(exchange, 200, Map.of("data", values), requestId);
            return;
        }
        if ("GET".equals(exchange.getRequestMethod())
                && "/v1/finance/exceptions".equals(path)) {
            requireScope(principal, ApiPrincipal.FINANCIAL_READ);
            List<Map<String, Object>> values = new ArrayList<>();
            service.exceptions(principal.tenantId().toString(), limit(query)).forEach(item -> {
                Map<String, Object> value = new LinkedHashMap<>();
                value.put("id", item.id());
                value.put("match_key", item.matchKey());
                value.put("status", item.status());
                value.put("owner", item.owner());
                value.put("adjustment_minor", item.adjustmentMinor());
                value.put("currency", item.currency());
                value.put("version", item.version());
                value.put("updated_at", item.updatedAt());
                values.add(value);
            });
            response(exchange, 200, Map.of("data", values), requestId);
            return;
        }
        if ("POST".equals(exchange.getRequestMethod())
                && path.startsWith("/v1/finance/exceptions/")) {
            requireScope(principal, ApiPrincipal.FINANCIAL_WRITE);
            String[] parts = path.substring("/v1/finance/exceptions/".length()).split("/", -1);
            if (parts.length != 2) {
                error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
                return;
            }
            Set<String> actionFields = switch (parts[1]) {
                case "claim", "reject-adjustment" -> Set.of("reason", "ticket_id");
                case "propose-adjustment" -> Set.of("reason", "ticket_id",
                        "adjustment_minor", "currency");
                case "approve-adjustment" -> Set.of("reason", "ticket_id",
                        "ledger_transaction_id");
                default -> throw new IllegalArgumentException("unknown exception action");
            };
            Map<String, Object> body = body(exchange, actionFields);
            FinancialOperationsService.ExceptionItem item = switch (parts[1]) {
                case "claim" -> service.claimException(principal.tenantId().toString(), parts[0],
                        principal.id(), string(body, "reason"), string(body, "ticket_id"));
                case "propose-adjustment" -> service.proposeAdjustment(
                        principal.tenantId().toString(), parts[0], principal.id(),
                        integer(body, "adjustment_minor"), string(body, "currency"),
                        string(body, "reason"), string(body, "ticket_id"));
                case "approve-adjustment" -> service.approveAdjustment(
                        principal.tenantId().toString(), parts[0], principal.id(),
                        string(body, "ledger_transaction_id"), string(body, "reason"),
                        string(body, "ticket_id"));
                case "reject-adjustment" -> service.rejectAdjustment(
                        principal.tenantId().toString(), parts[0], principal.id(),
                        string(body, "reason"), string(body, "ticket_id"));
                default -> throw new IllegalArgumentException("unknown exception action");
            };
            response(exchange, 200, exception(item), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private static Map<String, Object> body(HttpExchange exchange, Set<String> allowed)
            throws IOException {
        byte[] bytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) {
            throw new IllegalArgumentException("request body is too large");
        }
        Map<String, Object> value = Json.object(new String(bytes, StandardCharsets.UTF_8));
        if (!allowed.containsAll(value.keySet())) {
            throw new IllegalArgumentException("unknown request field");
        }
        return value;
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> values = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return values;
        }
        for (String pair : raw.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("invalid query string");
            }
            String name = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            if (values.putIfAbsent(name, value) != null) {
                throw new IllegalArgumentException("duplicate query field");
            }
        }
        return values;
    }

    private static String string(Map<String, Object> value, String name) {
        Object item = value.get(name);
        if (!(item instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return text;
    }

    private static long integer(Map<String, Object> value, String name) {
        Object item = value.get(name);
        if (!(item instanceof Long number)) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
        return number;
    }

    private static Map<String, Object> exception(
            FinancialOperationsService.ExceptionItem item) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("id", item.id());
        value.put("match_key", item.matchKey());
        value.put("status", item.status());
        value.put("owner", item.owner());
        value.put("adjustment_minor", item.adjustmentMinor());
        value.put("currency", item.currency());
        value.put("version", item.version());
        value.put("updated_at", item.updatedAt());
        return value;
    }

    private static String required(Map<String, String> value, String name) {
        String item = value.get(name);
        if (item == null || item.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return item;
    }

    private static int limit(Map<String, String> query) {
        String value = query.getOrDefault("limit", "100");
        int parsed = Integer.parseInt(value);
        if (parsed <= 0 || parsed > 1_000) {
            throw new IllegalArgumentException("limit is out of range");
        }
        return parsed;
    }

    private static void requireScope(ApiPrincipal principal, String scope) {
        if (!principal.hasScope(scope)) {
            throw new AccessDeniedException("required API scope is missing");
        }
    }

    private static void requireProject(HttpExchange exchange, ApiPrincipal principal) {
        String value = exchange.getRequestHeaders().getFirst("X-Project-Id");
        if (value == null || !principal.projectId().equals(UUID.fromString(value))) {
            throw new AccessDeniedException("request project does not match the authenticated principal");
        }
    }

    private static boolean validRequestId(String value) {
        if (value == null) {
            return false;
        }
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static boolean validTraceparent(String value) {
        return value != null && value.matches(
                "00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}")
                && !value.substring(3, 35).equals("00000000000000000000000000000000")
                && !value.substring(36, 52).equals("0000000000000000");
    }

    private static String safe(String requestId) {
        return validRequestId(requestId) ? requestId : UUID.randomUUID().toString();
    }

    private static void response(HttpExchange exchange, int status, Map<String, Object> body,
            String requestId) throws IOException {
        byte[] bytes = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("X-Request-Id", requestId);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static void error(HttpExchange exchange, int status, String code, String message,
            String requestId) throws IOException {
        response(exchange, status, Map.of("error", Map.of("code", code, "message", message,
                "request_id", requestId)), requestId);
    }
}
