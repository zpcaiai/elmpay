package com.elmpay.webhook.ingress;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Reachable provider callback route: POST /v1/provider-webhooks/{opaque-token}. */
public final class WebhookIngressHttpHandler implements HttpHandler {
    public static final String PATH_PREFIX = "/v1/provider-webhooks/";
    private static final int MAX_BODY_BYTES = 1_048_576;
    private final WebhookIngressRuntime runtime;
    private final Clock clock;

    public WebhookIngressHttpHandler(WebhookIngressRuntime runtime, Clock clock) {
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        try (exchange) {
            if (!"POST".equals(exchange.getRequestMethod())) {
                respond(exchange, 405);
                return;
            }
            String path = exchange.getRequestURI().getRawPath();
            if (path == null || !path.startsWith(PATH_PREFIX)
                    || path.length() == PATH_PREFIX.length()) {
                respond(exchange, 404);
                return;
            }
            String endpointToken = path.substring(PATH_PREFIX.length());
            if (endpointToken.indexOf('/') >= 0) {
                respond(exchange, 404);
                return;
            }
            byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
            if (body.length > MAX_BODY_BYTES) {
                respond(exchange, 413);
                return;
            }
            try {
                WebhookIngressService.Receipt receipt = runtime.ingest(endpointToken,
                        canonicalHeaders(exchange), body, clock.instant());
                respond(exchange, receipt.outcome() == WebhookIngressService.Outcome.ACCEPTED
                        ? 202 : 200);
            } catch (SecurityException | IllegalArgumentException exception) {
                respond(exchange, 401);
            } catch (RuntimeException exception) {
                respond(exchange, 503);
            }
        }
    }

    private static Map<String, String> canonicalHeaders(HttpExchange exchange) {
        Map<String, String> result = new LinkedHashMap<>();
        exchange.getRequestHeaders().forEach((name, values) -> {
            List<String> safe = List.copyOf(values);
            if (safe.size() != 1 || safe.getFirst().length() > 8_192
                    || safe.getFirst().indexOf('\r') >= 0 || safe.getFirst().indexOf('\n') >= 0) {
                throw new SecurityException("provider webhook header is ambiguous");
            }
            String normalized = name.toLowerCase(Locale.ROOT);
            if (result.putIfAbsent(normalized, safe.getFirst()) != null) {
                throw new SecurityException("provider webhook header is duplicated");
            }
        });
        return Map.copyOf(result);
    }

    private static void respond(HttpExchange exchange, int status) throws IOException {
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
        exchange.sendResponseHeaders(status, -1);
    }
}
