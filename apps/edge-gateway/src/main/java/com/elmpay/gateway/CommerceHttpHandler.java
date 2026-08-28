package com.elmpay.gateway;

import com.elmpay.payment.commerce.CommerceRuntimeException;
import com.elmpay.payment.commerce.CommerceService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Authenticated B66-B71 administration boundary; verified provider events enter via workers. */
public final class CommerceHttpHandler implements HttpHandler {
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Set<String> PLAN_FIELDS = Set.of("code", "amount_minor", "currency",
            "billing_period_seconds", "trial_period_seconds", "metered", "version");
    private static final Set<String> MANDATE_FIELDS = Set.of("customer_reference", "provider",
            "provider_mandate_reference", "payment_method_reference", "purpose",
            "maximum_amount_minor", "currency", "consent_digest");
    private static final Set<String> SUBSCRIPTION_FIELDS = Set.of("customer_reference", "plan_id",
            "mandate_id");
    private static final Set<String> USAGE_FIELDS = Set.of("quantity");
    private static final Set<String> CHANGE_PLAN_FIELDS = Set.of("plan_id", "reason");
    private static final Set<String> CANCEL_FIELDS = Set.of("cancel_at", "reason");
    private static final Set<String> EVIDENCE_FIELDS = Set.of("object_digest", "media_type",
            "object_reference");

    private final ApiKeyAuthenticator authenticator;
    private final Optional<CommerceService> commerce;
    private final FixedWindowRateLimiter rateLimiter;

    public CommerceHttpHandler(ApiKeyAuthenticator authenticator,
            Optional<CommerceService> commerce) {
        this.authenticator = java.util.Objects.requireNonNull(authenticator, "authenticator");
        this.commerce = java.util.Objects.requireNonNull(commerce, "commerce");
        this.rateLimiter = new FixedWindowRateLimiter(120, 60, Clock.systemUTC());
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
            if (!rateLimiter.allow(principal.id())) {
                error(exchange, 429, "rate_limited", "request rate limit exceeded", requestId);
                return;
            }
            requireProject(exchange, principal);
            CommerceService service = commerce.orElseThrow(() ->
                    new CommerceRuntimeException("COMMERCE_NOT_READY",
                            "durable commerce runtime is not configured"));
            route(exchange, principal, service, requestId);
        } catch (AccessDeniedException denied) {
            error(exchange, 403, "forbidden", denied.getMessage(), safe(requestId));
        } catch (CommerceRuntimeException failure) {
            int status = switch (failure.code()) {
                case "RESOURCE_NOT_FOUND" -> 404;
                case "COMMERCE_NOT_READY", "COMMERCE_DATABASE_UNAVAILABLE",
                        "COMMERCE_PERSISTENCE_FAILURE" -> 503;
                case "CONCURRENT_MODIFICATION", "IDEMPOTENCY_CONFLICT",
                        "DISPUTE_IDENTITY_CONFLICT", "PROVIDER_EVENT_CONFLICT" -> 409;
                default -> 400;
            };
            error(exchange, status, failure.code().toLowerCase(java.util.Locale.ROOT),
                    failure.getMessage(), safe(requestId));
        } catch (IllegalArgumentException failure) {
            error(exchange, 400, "invalid_request", "request does not satisfy the API contract",
                    safe(requestId));
        } catch (RuntimeException failure) {
            error(exchange, 500, "internal_error", "request could not be completed",
                    safe(requestId));
        } finally {
            exchange.close();
        }
    }

    private void route(HttpExchange exchange, ApiPrincipal principal, CommerceService service,
            String requestId) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        CommerceService.Context context = new CommerceService.Context(principal.tenantId(),
                principal.projectId(), principal.id());
        if ("POST".equals(method) && "/v1/billing/plans".equals(path)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            Map<String, Object> body = body(exchange, PLAN_FIELDS);
            CommerceService.Plan value = service.createPlan(context,
                    new CommerceService.PlanCommand(string(body, "code"),
                            integer(body, "amount_minor"), string(body, "currency"),
                            integer(body, "billing_period_seconds"),
                            integer(body, "trial_period_seconds"), bool(body, "metered"),
                            integer(body, "version")),
                    idempotency(exchange), requestId);
            response(exchange, 201, plan(value), requestId);
            return;
        }
        if ("POST".equals(method) && "/v1/billing/mandates".equals(path)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            Map<String, Object> body = body(exchange, MANDATE_FIELDS);
            CommerceService.Mandate value = service.createMandate(context,
                    new CommerceService.MandateCommand(string(body, "customer_reference"),
                            string(body, "provider"), string(body, "provider_mandate_reference"),
                            string(body, "payment_method_reference"), string(body, "purpose"),
                            integer(body, "maximum_amount_minor"), string(body, "currency"),
                            string(body, "consent_digest")), idempotency(exchange), requestId);
            response(exchange, 201, mandate(value), requestId);
            return;
        }
        if ("POST".equals(method) && "/v1/billing/subscriptions".equals(path)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            Map<String, Object> body = body(exchange, SUBSCRIPTION_FIELDS);
            CommerceService.Subscription value = service.createSubscription(context,
                    new CommerceService.SubscriptionCommand(string(body, "customer_reference"),
                            UUID.fromString(string(body, "plan_id")),
                            UUID.fromString(string(body, "mandate_id"))),
                    idempotency(exchange), requestId);
            response(exchange, 201, subscription(value), requestId);
            return;
        }
        if (path.startsWith("/v1/billing/mandates/")) {
            mandateRoute(exchange, principal, service, context, path, requestId);
            return;
        }
        if (path.startsWith("/v1/billing/subscriptions/")) {
            subscriptionRoute(exchange, principal, service, context, path, requestId);
            return;
        }
        if (path.startsWith("/v1/disputes/")) {
            disputeRoute(exchange, principal, service, context, path, requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private void mandateRoute(HttpExchange exchange, ApiPrincipal principal,
            CommerceService service, CommerceService.Context context, String path,
            String requestId) throws IOException {
        String[] parts = path.substring("/v1/billing/mandates/".length()).split("/", -1);
        if (parts.length == 2 && "revoke".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            Map<String, Object> body = body(exchange, Set.of("reason"));
            CommerceService.Mandate value = service.revokeMandate(context,
                    UUID.fromString(parts[0]), string(body, "reason"), idempotency(exchange),
                    requestId);
            response(exchange, 200, mandate(value), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private void subscriptionRoute(HttpExchange exchange, ApiPrincipal principal,
            CommerceService service, CommerceService.Context context, String path,
            String requestId) throws IOException {
        String[] parts = path.substring("/v1/billing/subscriptions/".length()).split("/", -1);
        UUID id = UUID.fromString(parts[0]);
        if (parts.length == 1 && "GET".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_READ);
            response(exchange, 200, subscription(service.getSubscription(context, id)), requestId);
            return;
        }
        requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
        if (parts.length == 2 && "usage".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = body(exchange, USAGE_FIELDS);
            response(exchange, 200, subscription(service.recordUsage(context, id,
                    integer(body, "quantity"), idempotency(exchange), requestId)), requestId);
            return;
        }
        if (parts.length == 2 && "change-plan".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = body(exchange, CHANGE_PLAN_FIELDS);
            response(exchange, 200, adjustment(service.changePlan(context, id,
                    UUID.fromString(string(body, "plan_id")), string(body, "reason"),
                    idempotency(exchange), requestId)), requestId);
            return;
        }
        if (parts.length == 2 && "cancel".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = body(exchange, CANCEL_FIELDS);
            response(exchange, 200, adjustment(service.scheduleCancellation(context, id,
                    Instant.parse(string(body, "cancel_at")), string(body, "reason"),
                    idempotency(exchange), requestId)), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private void disputeRoute(HttpExchange exchange, ApiPrincipal principal,
            CommerceService service, CommerceService.Context context, String path,
            String requestId) throws IOException {
        String[] parts = path.substring("/v1/disputes/".length()).split("/", -1);
        UUID id = UUID.fromString(parts[0]);
        if (parts.length == 1 && "GET".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_READ);
            response(exchange, 200, dispute(service.getDispute(context, id)), requestId);
            return;
        }
        if (parts.length == 2 && "evidence".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            Map<String, Object> body = body(exchange, EVIDENCE_FIELDS);
            CommerceService.Dispute value = service.submitEvidence(context, id,
                    string(body, "object_digest"), string(body, "media_type"),
                    string(body, "object_reference"), idempotency(exchange), requestId);
            response(exchange, 200, dispute(value), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private static Map<String, Object> plan(CommerceService.Plan value) {
        return Map.of("id", value.id(), "code", value.code(), "amount_minor",
                value.amountMinor(), "currency", value.currency(), "billing_period_seconds",
                value.billingPeriodSeconds(), "trial_period_seconds", value.trialPeriodSeconds(),
                "metered", value.metered(), "version", value.version());
    }

    private static Map<String, Object> mandate(CommerceService.Mandate value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", value.id());
        result.put("customer_reference", value.customerReference());
        result.put("provider", value.provider());
        result.put("purpose", value.purpose());
        result.put("maximum_amount_minor", value.maximumAmountMinor());
        result.put("currency", value.currency());
        result.put("state", value.state());
        result.put("consented_at", value.consentedAt());
        result.put("revoked_at", value.revokedAt());
        result.put("version", value.version());
        return result;
    }

    private static Map<String, Object> subscription(CommerceService.Subscription value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", value.id());
        result.put("customer_reference", value.customerReference());
        result.put("plan_id", value.planId());
        result.put("mandate_id", value.mandateId());
        result.put("state", value.state());
        result.put("period_start", value.periodStart());
        result.put("period_end", value.periodEnd());
        result.put("usage_quantity", value.usageQuantity());
        result.put("cancel_at", value.cancelAt());
        result.put("version", value.version());
        return result;
    }

    private static Map<String, Object> adjustment(CommerceService.Adjustment value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", value.id());
        result.put("subscription_id", value.subscriptionId());
        result.put("operation", value.operation());
        result.put("old_plan_id", value.oldPlanId());
        result.put("new_plan_id", value.newPlanId());
        result.put("old_unused_credit_minor", value.oldUnusedCreditMinor());
        result.put("new_remaining_charge_minor", value.newRemainingChargeMinor());
        result.put("net_debit_minor", value.netDebitMinor());
        result.put("currency", value.currency());
        result.put("remaining_seconds", value.remainingSeconds());
        result.put("period_seconds", value.periodSeconds());
        result.put("created_at", value.createdAt());
        return result;
    }

    private static Map<String, Object> dispute(CommerceService.Dispute value) {
        return Map.of("id", value.id(), "provider", value.provider(), "provider_dispute_id",
                value.providerDisputeId(), "payment_intent_id", value.paymentIntentId(),
                "amount_minor", value.amountMinor(), "currency", value.currency(),
                "response_deadline", value.responseDeadline(), "state", value.state(),
                "financial_effect_state", value.financialEffectState(), "version", value.version());
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

    private static String string(Map<String, Object> body, String name) {
        Object value = body.get(name);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return text;
    }

    private static long integer(Map<String, Object> body, String name) {
        Object value = body.get(name);
        if (!(value instanceof Long number)) {
            throw new IllegalArgumentException(name + " must be an integer");
        }
        return number;
    }

    private static boolean bool(Map<String, Object> body, String name) {
        Object value = body.get(name);
        if (!(value instanceof Boolean flag)) {
            throw new IllegalArgumentException(name + " must be boolean");
        }
        return flag;
    }

    private static String idempotency(HttpExchange exchange) {
        String value = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Idempotency-Key is required");
        }
        return value;
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
