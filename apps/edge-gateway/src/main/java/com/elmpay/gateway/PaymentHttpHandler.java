package com.elmpay.gateway;

import com.elmpay.money.Money;
import com.elmpay.idempotency.IdempotencyException;
import com.elmpay.payment.CaptureCommand;
import com.elmpay.payment.ConfirmationCommand;
import com.elmpay.payment.ConfirmationMode;
import com.elmpay.payment.ConfirmationResult;
import com.elmpay.payment.CreateIntentCommand;
import com.elmpay.payment.IntentActionCommand;
import com.elmpay.payment.PaymentAttempt;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.PaymentIntent;
import com.elmpay.payment.PaymentMethodReference;
import com.elmpay.payment.PaymentService;
import com.elmpay.payment.checkout.HostedCheckoutService;
import com.elmpay.payment.refund.RefundApplicationService;
import com.elmpay.payment.refund.RefundApprovalCommand;
import com.elmpay.payment.refund.RefundReason;
import com.elmpay.payment.refund.RefundRecord;
import com.elmpay.payment.refund.RefundRecoveryCommand;
import com.elmpay.payment.refund.RefundRequestCommand;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Public HTTP boundary. Tenant identity comes only from the authenticated principal. */
public final class PaymentHttpHandler implements HttpHandler {
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Set<String> CREATE_FIELDS = Set.of("external_reference", "amount_minor",
            "currency", "allowed_methods", "confirmation_mode", "region", "ttl_minutes",
            "business_order_no", "amount", "capture_method", "allowed_payment_methods",
            "metadata");
    private static final Set<String> CONFIRM_FIELDS = Set.of("method", "payment_method_type",
            "payment_method_reference", "fingerprint", "approved_return_route_id",
            "return_url_token", "provider_parameters");
    private static final Set<String> CHECKOUT_CREATE_FIELDS = Set.of("business_order_no", "amount",
            "currency", "return_route_id");
    private static final Set<String> CHECKOUT_CONFIRM_FIELDS = Set.of("payment_method_type",
            "payment_method_reference", "fingerprint", "provider_parameters", "method");
    private static final Set<String> REFUND_CREATE_FIELDS = Set.of("payment_intent_id", "amount",
            "reason");
    private static final Set<String> REFUND_APPROVE_FIELDS = Set.of("reason", "ticket_id");
    private static final Set<String> REFUND_RECOVER_FIELDS = Set.of("ticket_id");
    private final RuntimeComponents runtime;
    private final HostedCheckoutService checkout;
    private final FixedWindowRateLimiter rateLimiter;

    public PaymentHttpHandler(RuntimeComponents runtime) {
        this(runtime, localCheckout(runtime));
    }

    public PaymentHttpHandler(RuntimeComponents runtime, HostedCheckoutService checkout) {
        this.runtime = java.util.Objects.requireNonNull(runtime, "runtime");
        this.checkout = java.util.Objects.requireNonNull(checkout, "checkout");
        this.rateLimiter = new FixedWindowRateLimiter(120, 60, Clock.systemUTC());
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = validRequestId(exchange.getRequestHeaders().getFirst("X-Request-Id"));
        try {
            if (health(exchange, requestId)) {
                return;
            }
            if (requestId == null || !validTraceparent(
                    exchange.getRequestHeaders().getFirst("traceparent"))) {
                error(exchange, 400, "invalid_request",
                        "X-Request-Id and a valid traceparent are required", safeRequestId(requestId));
                return;
            }
            if (exchange.getRequestURI().getPath().startsWith("/api/checkout/sessions/")) {
                browserCheckoutRoute(exchange, requestId);
                return;
            }
            ApiPrincipal principal = runtime.authenticator().authenticate(exchange.getRequestHeaders())
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
            route(exchange, principal, requestId);
        } catch (PaymentCoreException exception) {
            error(exchange, status(exception.code()), apiCode(exception.code()), exception.getMessage(),
                    safeRequestId(requestId));
        } catch (IdempotencyException exception) {
            error(exchange, 400, "invalid_idempotency_key", exception.getMessage(),
                    safeRequestId(requestId));
        } catch (SecurityException exception) {
            error(exchange, 401, "invalid_checkout_token",
                    "checkout authorization is invalid or expired", safeRequestId(requestId));
        } catch (AccessDeniedException exception) {
            error(exchange, 403, "forbidden", exception.getMessage(), safeRequestId(requestId));
        } catch (IllegalArgumentException exception) {
            error(exchange, 400, "invalid_request", "request does not satisfy the API contract",
                    safeRequestId(requestId));
        } catch (RuntimeException exception) {
            error(exchange, 500, "internal_error", "request could not be completed",
                    safeRequestId(requestId));
        } finally {
            exchange.close();
        }
    }

    private boolean health(HttpExchange exchange, String requestId) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if ("/health/live".equals(path)) {
            response(exchange, 200, Map.of("status", "live", "mode", runtime.mode()),
                    safeRequestId(requestId));
            return true;
        }
        if ("/health/ready".equals(path)) {
            response(exchange, runtime.ready() ? 200 : 503,
                    Map.of("status", runtime.ready() ? "ready" : "not_ready", "mode", runtime.mode()),
                    safeRequestId(requestId));
            return true;
        }
        return false;
    }

    private void route(HttpExchange exchange, ApiPrincipal principal, String requestId)
            throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        if ("POST".equals(method) && "/v1/payment-intents".equals(path)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            create(exchange, principal, requestId);
            return;
        }
        if ("POST".equals(method) && "/v1/checkout-sessions".equals(path)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            createCheckout(exchange, principal, requestId);
            return;
        }
        if (path.startsWith("/v1/checkout-sessions/")) {
            authenticatedCheckoutRoute(exchange, principal, requestId);
            return;
        }
        if ("/v1/refunds".equals(path) && "POST".equals(method)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            createRefund(exchange, principal, requestId);
            return;
        }
        if (path.startsWith("/v1/refunds/")) {
            refundRoute(exchange, principal, requestId);
            return;
        }
        String prefix = "/v1/payment-intents/";
        if (!path.startsWith(prefix)) {
            error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
            return;
        }
        requireProject(exchange, principal);
        String tail = path.substring(prefix.length());
        String[] parts = tail.split("/", -1);
        UUID intentId = UUID.fromString(parts[0]);
        if (parts.length == 1 && "GET".equals(method)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_READ);
            response(exchange, 200, intent(runtime.payments().get(principal.tenantId(), intentId)),
                    requestId);
        } else if (parts.length == 2 && "POST".equals(method)) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            action(exchange, principal, intentId, parts[1], requestId);
        } else {
            error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
        }
    }

    private void createCheckout(HttpExchange exchange, ApiPrincipal principal, String requestId)
            throws IOException {
        requireProject(exchange, principal);
        Map<String, Object> body = body(exchange);
        requireOnly(body, CHECKOUT_CREATE_FIELDS);
        HostedCheckoutService.Created created = checkout.create(
                new HostedCheckoutService.CreateCommand(principal.tenantId(), principal.projectId(),
                        principal.merchantId(), string(body, "business_order_no"),
                        integer(body, "amount"), string(body, "currency"),
                        optionalString(body, "return_route_id"),
                        exchange.getRequestHeaders().getFirst("X-Device-Context-Digest"),
                        requiredHeader(exchange, "Idempotency-Key")));
        response(exchange, 201, Map.of("checkout_session_id", created.checkoutSessionId(),
                "expires_at", created.expiresAt(), "checkout_url", created.checkoutUrl().toString(),
                "status", created.status()), requestId);
    }

    private void createRefund(HttpExchange exchange, ApiPrincipal principal, String requestId)
            throws IOException {
        requireProject(exchange, principal);
        RefundApplicationService refunds = requireRefundRuntime();
        Map<String, Object> body = body(exchange);
        requireOnly(body, REFUND_CREATE_FIELDS);
        String deviceDigest = requiredHeader(exchange, "X-Device-Context-Digest");
        if (!deviceDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("X-Device-Context-Digest must be a SHA-256 digest");
        }
        RefundRecord refund = refunds.request(new RefundRequestCommand(principal.tenantId(),
                UUID.fromString(string(body, "payment_intent_id")), integer(body, "amount"),
                RefundReason.valueOf(string(body, "reason").toUpperCase(Locale.ROOT)),
                principal.id(), deviceDigest, requiredHeader(exchange, "Idempotency-Key"),
                requestId));
        response(exchange, 201, refund(refund, principal), requestId);
    }

    private void refundRoute(HttpExchange exchange, ApiPrincipal principal, String requestId)
            throws IOException {
        requireProject(exchange, principal);
        RefundApplicationService refunds = requireRefundRuntime();
        String tail = exchange.getRequestURI().getPath().substring("/v1/refunds/".length());
        String[] parts = tail.split("/", -1);
        UUID refundId = UUID.fromString(parts[0]);
        if (parts.length == 1 && "GET".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_READ);
            RefundRecord value = refunds.get(principal.tenantId(), refundId);
            requireRefundProject(value, principal);
            response(exchange, 200, refund(value, principal), requestId);
            return;
        }
        requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
        if (parts.length == 2 && "approve".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = body(exchange);
            requireOnly(body, REFUND_APPROVE_FIELDS);
            RefundRecord current = refunds.get(principal.tenantId(), refundId);
            requireRefundProject(current, principal);
            RefundRecord value = refunds.approve(new RefundApprovalCommand(principal.tenantId(),
                    refundId, principal.id(), string(body, "reason"), string(body, "ticket_id"),
                    requiredHeader(exchange, "Idempotency-Key"), requestId));
            response(exchange, 200, refund(value, principal), requestId);
            return;
        }
        if (parts.length == 2 && "recover".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = body(exchange);
            requireOnly(body, REFUND_RECOVER_FIELDS);
            RefundRecord current = refunds.get(principal.tenantId(), refundId);
            requireRefundProject(current, principal);
            RefundRecord value = refunds.recover(new RefundRecoveryCommand(principal.tenantId(),
                    refundId, principal.id(), string(body, "ticket_id"),
                    requiredHeader(exchange, "Idempotency-Key"), requestId));
            response(exchange, 200, refund(value, principal), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private RefundApplicationService requireRefundRuntime() {
        if (runtime.refunds() == null) {
            throw new IllegalStateException("refund runtime is not configured");
        }
        return runtime.refunds();
    }

    private static void requireRefundProject(RefundRecord value, ApiPrincipal principal) {
        if (!principal.projectId().equals(value.projectId())) {
            throw new PaymentCoreException("RESOURCE_NOT_FOUND", "refund does not exist in this project");
        }
    }

    private static Map<String, Object> refund(RefundRecord value, ApiPrincipal principal) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", value.id());
        result.put("project_id", value.projectId());
        result.put("payment_intent_id", value.paymentIntentId());
        result.put("amount", value.amount().amountMinor());
        result.put("currency", value.amount().currency().code());
        result.put("status", value.status().name().toLowerCase(Locale.ROOT));
        result.put("reason", value.reason().wireValue());
        result.put("risk_decision", value.riskDecision().name().toLowerCase(Locale.ROOT));
        result.put("provider_refund_id", value.providerRefundId());
        result.put("failure_code", value.failureCode());
        result.put("created_at", value.createdAt());
        result.put("updated_at", value.updatedAt());
        result.put("version", value.version());
        return result;
    }

    private void authenticatedCheckoutRoute(HttpExchange exchange, ApiPrincipal principal,
            String requestId) throws IOException {
        requireProject(exchange, principal);
        String path = exchange.getRequestURI().getPath();
        String tail = path.substring("/v1/checkout-sessions/".length());
        String[] parts = tail.split("/", -1);
        requireSessionId(parts[0]);
        if (parts.length == 1 && "GET".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_READ);
            response(exchange, 200, canonicalCheckout(checkout.getForPrincipal(principal.tenantId(),
                    principal.projectId(), parts[0])), requestId);
            return;
        }
        if (parts.length == 2 && "confirm".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            requireScope(principal, ApiPrincipal.PAYMENTS_WRITE);
            Map<String, Object> body = body(exchange);
            requireOnly(body, CHECKOUT_CONFIRM_FIELDS);
            HostedCheckoutService.View view = checkout.confirmForPrincipal(principal.tenantId(),
                    principal.projectId(), parts[0], checkoutConfirm(body,
                            requiredHeader(exchange, "Idempotency-Key"), requestId));
            response(exchange, 200, canonicalCheckout(view), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private void browserCheckoutRoute(HttpExchange exchange, String requestId) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String tail = path.substring("/api/checkout/sessions/".length());
        String[] parts = tail.split("/", -1);
        requireSessionId(parts[0]);
        String token = checkoutToken(exchange);
        if (!rateLimiter.allow("checkout:" + parts[0])) {
            error(exchange, 429, "rate_limited", "request rate limit exceeded", requestId);
            return;
        }
        if (parts.length == 1 && "GET".equals(exchange.getRequestMethod())) {
            response(exchange, 200, browserCheckout(checkout.getForBrowser(parts[0], token)),
                    requestId);
            return;
        }
        if (parts.length == 2 && "confirm".equals(parts[1])
                && "POST".equals(exchange.getRequestMethod())) {
            Map<String, Object> body = body(exchange);
            requireOnly(body, Set.of("method"));
            Map<String, Object> normalized = Map.of("method", string(body, "method"));
            HostedCheckoutService.View view = checkout.confirmForBrowser(parts[0], token,
                    checkoutConfirm(normalized, requiredHeader(exchange, "Idempotency-Key"),
                            requestId));
            response(exchange, 200, browserCheckout(view), requestId);
            return;
        }
        error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
    }

    private static HostedCheckoutService.ConfirmCommand checkoutConfirm(Map<String, Object> body,
            String idempotencyKey, String requestId) {
        String method = optionalString(body, "payment_method_type");
        if (method == null) {
            method = string(body, "method");
        }
        return new HostedCheckoutService.ConfirmCommand(method,
                optionalString(body, "payment_method_reference"),
                optionalString(body, "fingerprint"), optionalStringMap(body,
                        "provider_parameters"), idempotencyKey, requestId);
    }

    private static Map<String, Object> canonicalCheckout(HostedCheckoutService.View view) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("checkout_session_id", view.checkoutSessionId());
        result.put("payment_intent_id", view.paymentIntentId());
        result.put("business_order_no", view.businessOrderNo());
        result.put("amount", view.amount());
        result.put("currency", view.currency());
        result.put("return_route_id", view.returnRouteId());
        result.put("expires_at", view.expiresAt());
        result.put("status", view.status());
        result.put("next_action", view.nextAction());
        return result;
    }

    private static Map<String, Object> browserCheckout(HostedCheckoutService.View view) {
        List<Map<String, Object>> methods = view.methods().stream().map(method ->
                Map.<String, Object>of("id", method.id(), "label", method.label(),
                        "eligible", method.eligible(), "reason", method.reason())).toList();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("checkoutSessionId", view.checkoutSessionId());
        result.put("status", view.status());
        result.put("displayAmount", view.displayAmount());
        result.put("locale", view.locale());
        result.put("direction", view.direction());
        result.put("methods", methods);
        result.put("nextAction", view.nextAction());
        return result;
    }

    private static void requireProject(HttpExchange exchange, ApiPrincipal principal) {
        String project = requiredHeader(exchange, "X-Project-Id");
        if (!principal.projectId().toString().equals(project)) {
            throw new AccessDeniedException(
                    "project context does not match the authenticated principal");
        }
    }

    private static void requireScope(ApiPrincipal principal, String scope) {
        if (!principal.hasScope(scope)) {
            throw new AccessDeniedException("authenticated principal lacks " + scope + " scope");
        }
    }

    private static String checkoutToken(HttpExchange exchange) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        String prefix = "CheckoutSession ";
        if (authorization == null || !authorization.startsWith(prefix)
                || !authorization.substring(prefix.length()).matches(
                        "[A-Za-z0-9_-]{48}\\.[A-Za-z0-9_-]{43}")) {
            throw new SecurityException("checkout token is required");
        }
        return authorization.substring(prefix.length());
    }

    private static void requireSessionId(String value) {
        if (value == null || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
            throw new IllegalArgumentException("checkout session id is invalid");
        }
    }

    private static HostedCheckoutService localCheckout(RuntimeComponents runtime) {
        if (!"local".equals(runtime.mode())) {
            throw new IllegalStateException(
                    "production checkout requires explicit signing and return-route configuration");
        }
        return CheckoutRuntimeFactory.local(runtime.payments());
    }

    private void create(HttpExchange exchange, ApiPrincipal principal, String requestId)
            throws IOException {
        requireProject(exchange, principal);
        Map<String, Object> body = body(exchange);
        requireOnly(body, CREATE_FIELDS);
        boolean canonical = body.containsKey("business_order_no") || body.containsKey("amount")
                || body.containsKey("capture_method") || body.containsKey("metadata");
        String idempotencyKey = requiredHeader(exchange, "Idempotency-Key");
        CreateIntentCommand command;
        Map<String, String> metadata = Map.of();
        if (canonical) {
            String captureMethod = optionalString(body, "capture_method");
            ConfirmationMode mode = captureMethod == null
                    || "automatic".equals(captureMethod)
                    ? ConfirmationMode.AUTOMATIC
                    : "manual".equals(captureMethod)
                            ? ConfirmationMode.MANUAL_CAPTURE
                            : throwInvalid("capture_method");
            Set<String> methods = body.containsKey("allowed_payment_methods")
                    ? strings(body, "allowed_payment_methods") : Set.of("stripe_card");
            command = new CreateIntentCommand(principal.tenantId(), principal.projectId(),
                    principal.merchantId(), string(body, "business_order_no"),
                    Money.of(integer(body, "amount"), string(body, "currency")), methods, mode,
                    optionalHeader(exchange, "X-Region", "US"),
                    Duration.ofMinutes(optionalInteger(body, "ttl_minutes", 60)), idempotencyKey);
            metadata = optionalMetadata(body, "metadata");
        } else {
            command = new CreateIntentCommand(principal.tenantId(),
                    principal.projectId(), principal.merchantId(), string(body, "external_reference"),
                    Money.of(integer(body, "amount_minor"), string(body, "currency")),
                    strings(body, "allowed_methods"),
                    ConfirmationMode.valueOf(string(body, "confirmation_mode").toUpperCase(Locale.ROOT)),
                    string(body, "region"), Duration.ofMinutes(integer(body, "ttl_minutes")),
                    idempotencyKey);
        }
        PaymentIntent created = runtime.payments().create(command);
        if (runtime.metadata() != null) {
            runtime.metadata().bind(principal.tenantId(), principal.projectId(), created.id(),
                    idempotencyKey, metadata);
        }
        response(exchange, 201, intent(created), requestId);
    }

    private void action(HttpExchange exchange, ApiPrincipal principal, UUID intentId,
            String action, String requestId) throws IOException {
        PaymentService payments = runtime.payments();
        switch (action) {
            case "confirm" -> confirm(exchange, principal, intentId, requestId);
            case "capture" -> {
                Map<String, Object> body = body(exchange);
                requireOnly(body, Set.of("amount_minor", "amount"));
                long amount = body.containsKey("amount") ? integer(body, "amount")
                        : integer(body, "amount_minor");
                ConfirmationResult result = payments.capture(new CaptureCommand(principal.tenantId(),
                        intentId, amount,
                        requiredHeader(exchange, "Idempotency-Key"), requestId));
                response(exchange, 200, confirmation(result), requestId);
            }
            case "cancel" -> {
                Map<String, Object> body = body(exchange);
                requireOnly(body, Set.of("reason"));
                PaymentIntent canceled = payments.cancel(new IntentActionCommand(principal.tenantId(),
                        intentId, requiredHeader(exchange, "Idempotency-Key"), requestId,
                        string(body, "reason")));
                response(exchange, 200, intent(canceled), requestId);
            }
            case "void" -> {
                Map<String, Object> body = body(exchange);
                requireOnly(body, Set.of("reason"));
                ConfirmationResult result = payments.voidAuthorization(new IntentActionCommand(
                        principal.tenantId(), intentId, requiredHeader(exchange, "Idempotency-Key"),
                        requestId, string(body, "reason")));
                response(exchange, 200, confirmation(result), requestId);
            }
            case "resolve" -> {
                requireOnly(body(exchange), Set.of());
                response(exchange, 200, confirmation(payments.resolveUnknown(
                        principal.tenantId(), intentId, requestId)), requestId);
            }
            default -> error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
        }
    }

    private void confirm(HttpExchange exchange, ApiPrincipal principal, UUID intentId,
            String requestId) throws IOException {
        Map<String, Object> body = body(exchange);
        requireOnly(body, CONFIRM_FIELDS);
        String method = optionalString(body, "method");
        if (method == null) {
            method = string(body, "payment_method_type");
        }
        String route = optionalString(body, "approved_return_route_id");
        if (route == null) {
            route = optionalString(body, "return_url_token");
        }
        Map<String, String> parameters = optionalStringMap(body, "provider_parameters");
        ConfirmationCommand command = new ConfirmationCommand(principal.tenantId(), intentId,
                PaymentMethodReference.parse(method,
                        string(body, "payment_method_reference"), string(body, "fingerprint")),
                requiredHeader(exchange, "Idempotency-Key"), requestId, route, parameters);
        response(exchange, 200, confirmation(runtime.payments().confirm(command)), requestId);
    }

    private static Map<String, Object> intent(PaymentIntent value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", value.id());
        result.put("project_id", value.projectId());
        result.put("business_order_no", value.externalReference());
        result.put("amount", value.amount().amountMinor());
        result.put("amount_captured", value.capturedAmountMinor());
        result.put("amount_refunded", value.refundedAmountMinor());
        result.put("status", canonicalStatus(value.state()));
        result.put("external_reference", value.externalReference());
        result.put("amount_minor", value.amount().amountMinor());
        result.put("currency", value.amount().currency().code());
        result.put("captured_amount_minor", value.capturedAmountMinor());
        result.put("refunded_amount_minor", value.refundedAmountMinor());
        result.put("state", value.state());
        result.put("allowed_methods", value.allowedMethods());
        result.put("confirmation_mode", value.confirmationMode());
        result.put("region", value.region());
        result.put("expires_at", value.expiresAt());
        result.put("created_at", value.createdAt());
        result.put("updated_at", value.updatedAt());
        result.put("version", value.version());
        return result;
    }

    private static String canonicalStatus(com.elmpay.payment.IntentState state) {
        return switch (state) {
            case CREATED -> "requires_payment_method";
            case REQUIRES_ACTION -> "requires_action";
            case AUTHORIZED -> "requires_capture";
            case CAPTURED -> "succeeded";
            case FAILED -> "failed";
            case CANCELED -> "canceled";
            case EXPIRED -> "failed";
        };
    }

    private static Map<String, Object> confirmation(ConfirmationResult value) {
        PaymentAttempt attempt = value.attempt();
        return Map.of("payment_intent", intent(value.intent()), "attempt", Map.ofEntries(
                Map.entry("id", attempt.id()), Map.entry("provider", attempt.provider()),
                Map.entry("operation", attempt.operation()), Map.entry("sequence", attempt.sequence()),
                Map.entry("state", attempt.state()), Map.entry("outcome_class", attempt.outcomeClass()),
                Map.entry("provider_code", attempt.providerCode() == null ? "" : attempt.providerCode())),
                "client_action", value.clientAction(), "replayed", value.replayed());
    }

    private static Map<String, Object> body(HttpExchange exchange) throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT)
                .startsWith("application/json")) {
            throw new IllegalArgumentException("application/json is required");
        }
        byte[] bytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) {
            throw new IllegalArgumentException("request body is too large");
        }
        return Json.object(new String(bytes, StandardCharsets.UTF_8));
    }

    private static void requireOnly(Map<String, Object> body, Set<String> allowed) {
        if (!allowed.containsAll(body.keySet())) {
            throw new IllegalArgumentException("unknown request field");
        }
    }

    private static String string(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("required string field is missing");
        }
        return text;
    }

    private static String optionalString(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("optional field must be a non-empty string");
        }
        return text;
    }

    private static long optionalInteger(Map<String, Object> body, String key, long fallback) {
        Object value = body.get(key);
        if (value == null) {
            return fallback;
        }
        if (!(value instanceof Long number) || number <= 0) {
            throw new IllegalArgumentException(key + " must be a positive integer");
        }
        return number;
    }

    private static String optionalHeader(HttpExchange exchange, String name, String fallback) {
        String value = exchange.getRequestHeaders().getFirst(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static Map<String, String> optionalMetadata(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (value == null) {
            return Map.of();
        }
        if (!(value instanceof Map<?, ?> map) || map.size() > 20) {
            throw new IllegalArgumentException("metadata must be an object with at most 20 values");
        }
        Map<String, String> result = new LinkedHashMap<>();
        map.forEach((field, fieldValue) -> {
            if (!(field instanceof String name) || name.isBlank() || name.length() > 128
                    || !(fieldValue instanceof String text) || text.length() > 256) {
                throw new IllegalArgumentException("metadata must contain bounded string values");
            }
            result.put(name, text);
        });
        return Map.copyOf(result);
    }

    private static <T> T throwInvalid(String field) {
        throw new IllegalArgumentException(field + " is invalid");
    }

    private static long integer(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof Long number)) {
            throw new IllegalArgumentException("required integer field is missing");
        }
        return number.longValue();
    }

    private static Set<String> strings(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (!(value instanceof List<?> list) || list.isEmpty()) {
            throw new IllegalArgumentException("required string list is missing");
        }
        Set<String> result = new LinkedHashSet<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank()) {
                throw new IllegalArgumentException("list contains a non-string value");
            }
            result.add(text);
        }
        return Set.copyOf(result);
    }

    private static Map<String, String> optionalStringMap(Map<String, Object> body, String key) {
        Object value = body.get(key);
        if (value == null) {
            return Map.of();
        }
        if (!(value instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("provider_parameters must be an object");
        }
        Map<String, String> result = new LinkedHashMap<>();
        map.forEach((field, fieldValue) -> {
            if (!(field instanceof String name) || !(fieldValue instanceof String text)) {
                throw new IllegalArgumentException("provider parameter values must be strings");
            }
            result.put(name, text);
        });
        return Map.copyOf(result);
    }

    private static String requiredHeader(HttpExchange exchange, String name) {
        String value = exchange.getRequestHeaders().getFirst(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static String validRequestId(String value) {
        return value != null && value.matches("[A-Za-z0-9._:-]{8,128}") ? value : null;
    }

    private static boolean validTraceparent(String value) {
        return value != null && value.matches(
                "00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}")
                && !value.substring(3, 35).matches("0{32}")
                && !value.substring(36, 52).matches("0{16}");
    }

    private static String safeRequestId(String value) {
        return value == null ? UUID.randomUUID().toString() : value;
    }

    private static int status(String code) {
        return switch (code) {
            case "RESOURCE_NOT_FOUND" -> 404;
            case "ATTEMPT_IN_PROGRESS", "CONCURRENT_MODIFICATION" -> 409;
            case "PROVIDER_NOT_CONFIGURED", "NO_ELIGIBLE_PROVIDER",
                    "PROVIDER_ACCOUNT_REFUND_DISABLED" -> 503;
            case "REFUND_AMOUNT_EXCEEDS_REFUNDABLE", "REFUND_QUERY_TOO_EARLY",
                    "REFUND_APPROVAL_NOT_ALLOWED", "REFUND_FOUR_EYES_REQUIRED",
                    "REFUND_CAPABILITY_MISSING", "REFUND_NOT_ALLOWED" -> 409;
            default -> 400;
        };
    }

    private static String apiCode(String code) {
        return switch (code) {
            case "RESOURCE_NOT_FOUND" -> "resource_not_found";
            case "CONCURRENT_MODIFICATION", "ATTEMPT_IN_PROGRESS", "IDEMPOTENCY_KEY_REUSE" ->
                "idempotency_key_reuse";
            case "PROVIDER_NOT_CONFIGURED", "NO_ELIGIBLE_PROVIDER" -> "provider_unavailable";
            case "REFUND_AMOUNT_EXCEEDS_REFUNDABLE" -> "refund_amount_exceeds_refundable";
            case "REFUND_QUERY_TOO_EARLY" -> "refund_recovery_not_ready";
            case "REFUND_APPROVAL_NOT_ALLOWED", "REFUND_FOUR_EYES_REQUIRED" ->
                "refund_approval_required";
            case "REFUND_CAPABILITY_MISSING", "PROVIDER_ACCOUNT_REFUND_DISABLED" ->
                "refund_capability_missing";
            case "REFUND_RISK_DENIED" -> "refund_denied";
            case "STATE_TRANSITION_NOT_ALLOWED", "CANCEL_NOT_ALLOWED", "CAPTURE_NOT_ALLOWED",
                    "VOID_NOT_ALLOWED" -> "state_transition_not_allowed";
            default -> "invalid_request";
        };
    }

    private static void response(HttpExchange exchange, int status, Map<String, ?> value,
            String requestId) throws IOException {
        byte[] body = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("X-Request-Id", requestId);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static void error(HttpExchange exchange, int status, String code, String message,
            String requestId) throws IOException {
        response(exchange, status, Map.of("code", code, "message", message,
                "request_id", requestId), requestId);
    }
}
