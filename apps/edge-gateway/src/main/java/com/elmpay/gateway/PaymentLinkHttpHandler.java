package com.elmpay.gateway;

import com.elmpay.payment.checkout.DurablePaymentLinkService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Authenticated creation and one-time token redemption for durable links/QRs. */
public final class PaymentLinkHttpHandler implements HttpHandler {
    private static final int MAX_BODY_BYTES = 8_192;
    private final ApiAuthenticator authenticator;
    private final DurablePaymentLinkService links;
    private final FixedWindowRateLimiter rateLimiter = new FixedWindowRateLimiter(60, 60,
            Clock.systemUTC());

    public PaymentLinkHttpHandler(ApiAuthenticator authenticator,
            DurablePaymentLinkService links) {
        this.authenticator = java.util.Objects.requireNonNull(authenticator, "authenticator");
        this.links = java.util.Objects.requireNonNull(links, "links");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String requestId = null;
        try {
            StrictJsonHttpRequest.validateEnvelope(exchange);
            if (exchange.getRequestURI().getRawQuery() != null) {
                throw new IllegalArgumentException(
                        "payment-link API query parameters are not supported");
            }
            requestId = StrictJsonHttpRequest.optionalHeader(exchange, "X-Request-Id", 128);
            if (!validRequestId(requestId) || !validTraceparent(
                    StrictJsonHttpRequest.optionalHeader(exchange, "traceparent", 128))) {
                error(exchange, 400, "invalid_request",
                        "X-Request-Id and a valid traceparent are required", safe(requestId));
                return;
            }
            String path = exchange.getRequestURI().getPath();
            if ("POST".equals(exchange.getRequestMethod())
                    && "/api/payment-links/redeem".equals(path)) {
                redeem(exchange, requestId);
                return;
            }
            ApiPrincipal principal = authenticator.authenticate(exchange)
                    .orElse(null);
            if (principal == null) {
                error(exchange, 401, "unauthenticated", "valid bearer credentials are required",
                        requestId);
                return;
            }
            if (!principal.hasScope(ApiPrincipal.PAYMENTS_WRITE)) {
                throw new AccessDeniedException("payments.write scope is required");
            }
            requireProject(exchange, principal);
            if (!rateLimiter.allow(principal.id())) {
                error(exchange, 429, "rate_limited", "request rate limit exceeded", requestId);
                return;
            }
            if (!"POST".equals(exchange.getRequestMethod())
                    || !"/v1/payment-links".equals(path)) {
                error(exchange, 404, "resource_not_found", "resource does not exist", requestId);
                return;
            }
            Map<String, Object> body = body(exchange, Set.of("checkout_session_id", "ttl_seconds"));
            DurablePaymentLinkService.Link link = links.create(principal.tenantId(),
                    principal.projectId(), UUID.fromString(string(body, "checkout_session_id")),
                    Duration.ofSeconds(integer(body, "ttl_seconds")),
                    requiredHeader(exchange, "Idempotency-Key"));
            response(exchange, 201, Map.of("token", link.token(), "checkout_session_id",
                    link.checkoutSessionId(), "expires_at", link.expiresAt(), "qr_payload",
                    link.qrPayload()), requestId);
        } catch (AccessDeniedException denied) {
            error(exchange, 403, "forbidden", denied.getMessage(), safe(requestId));
        } catch (SecurityException invalid) {
            error(exchange, 401, "invalid_payment_link", "payment link is invalid or expired",
                    safe(requestId));
        } catch (IllegalArgumentException invalid) {
            error(exchange, 400, "invalid_request", "request does not satisfy the API contract",
                    safe(requestId));
        } catch (IllegalStateException failure) {
            error(exchange, 503, "payment_link_unavailable",
                    "payment-link operation could not be completed", safe(requestId));
        } finally {
            exchange.close();
        }
    }

    private void redeem(HttpExchange exchange, String requestId) throws IOException {
        String limiterKey = exchange.getRemoteAddress().getAddress().getHostAddress();
        if (!rateLimiter.allow("redeem:" + limiterKey)) {
            error(exchange, 429, "rate_limited", "request rate limit exceeded", requestId);
            return;
        }
        Map<String, Object> body = body(exchange, Set.of("token"));
        DurablePaymentLinkService.Redemption value = links.redeem(string(body, "token"));
        response(exchange, 200, Map.of("tenant_id", value.tenantId(), "project_id",
                value.projectId(), "checkout_session_id", value.checkoutSessionId(),
                "consumed_at", value.consumedAt()), requestId);
    }

    private static Map<String, Object> body(HttpExchange exchange, Set<String> allowed)
            throws IOException {
        return StrictJsonHttpRequest.body(exchange, MAX_BODY_BYTES, allowed);
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

    private static String requiredHeader(HttpExchange exchange, String name) {
        return StrictJsonHttpRequest.requiredHeader(exchange, name, 128);
    }

    private static void requireProject(HttpExchange exchange, ApiPrincipal principal) {
        String value = StrictJsonHttpRequest.requiredHeader(exchange, "X-Project-Id", 64);
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
        byte[] raw = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("X-Request-Id", requestId);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, raw.length);
        exchange.getResponseBody().write(raw);
    }

    private static void error(HttpExchange exchange, int status, String code, String message,
            String requestId) throws IOException {
        response(exchange, status, Map.of("error", Map.of("code", code, "message", message,
                "request_id", requestId)), requestId);
    }
}
