package com.elmpay.webhook.ingress;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Arrays;

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
            URI request = exchange.getRequestURI();
            String path = request.getRawPath();
            if (request.isAbsolute() || request.getRawAuthority() != null
                    || request.getRawQuery() != null || request.getRawFragment() != null
                    || path == null || path.length() > 512 || path.indexOf('%') >= 0
                    || !path.equals(request.getPath())
                    || !path.equals(request.normalize().getRawPath()) || path.contains("//")
                    || !path.startsWith(PATH_PREFIX)
                    || path.length() == PATH_PREFIX.length()) {
                respond(exchange, 404);
                return;
            }
            String endpointToken = path.substring(PATH_PREFIX.length());
            if (!endpointToken.matches("[A-Za-z0-9_-]{32,256}")) {
                respond(exchange, 404);
                return;
            }
            Map<String, String> headers;
            try {
                headers = canonicalHeaders(exchange);
            } catch (SecurityException | IllegalArgumentException exception) {
                respond(exchange, 400);
                return;
            }
            long declaredLength = -1;
            String contentLength = headers.get("content-length");
            if (contentLength != null) {
                if (!contentLength.matches("(?:0|[1-9][0-9]{0,8})")) {
                    respond(exchange, 400);
                    return;
                }
                declaredLength = Long.parseLong(contentLength);
                if (declaredLength > MAX_BODY_BYTES) {
                    respond(exchange, 413);
                    return;
                }
            }
            byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
            try {
                if (body.length > MAX_BODY_BYTES
                        || (declaredLength >= 0 && body.length != declaredLength)) {
                    respond(exchange, 413);
                    return;
                }
                try {
                    WebhookIngressService.Receipt receipt = runtime.ingest(endpointToken,
                            headers, body, clock.instant());
                    respond(exchange, receipt.outcome() == WebhookIngressService.Outcome.ACCEPTED
                            ? 202 : 200);
                } catch (SecurityException | IllegalArgumentException exception) {
                    respond(exchange, 401);
                } catch (RuntimeException exception) {
                    respond(exchange, 503);
                }
            } finally {
                Arrays.fill(body, (byte) 0);
            }
        }
    }

    private static Map<String, String> canonicalHeaders(HttpExchange exchange) {
        Map<String, String> result = new LinkedHashMap<>();
        int[] aggregateBytes = {0};
        exchange.getRequestHeaders().forEach((name, values) -> {
            List<String> safe = List.copyOf(values);
            if (name == null || !name.matches("[A-Za-z0-9-]{1,64}")
                    || safe.size() != 1 || safe.getFirst().isBlank()
                    || safe.getFirst().length() > 8_192
                    || safe.getFirst().chars().anyMatch(character -> character < 0x20
                            || character == 0x7f)) {
                throw new SecurityException("provider webhook header is ambiguous");
            }
            aggregateBytes[0] = Math.addExact(aggregateBytes[0],
                    Math.addExact(name.length(), safe.getFirst().length()));
            if (result.size() >= 128 || aggregateBytes[0] > 65_536) {
                throw new SecurityException("provider webhook headers exceed their bound");
            }
            String normalized = name.toLowerCase(Locale.ROOT);
            if (result.putIfAbsent(normalized, safe.getFirst()) != null) {
                throw new SecurityException("provider webhook header is duplicated");
            }
        });
        if (result.containsKey("content-length") && result.containsKey("transfer-encoding")) {
            throw new SecurityException("provider webhook framing is ambiguous");
        }
        return Map.copyOf(result);
    }

    private static void respond(HttpExchange exchange, int status) throws IOException {
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'");
        exchange.sendResponseHeaders(status, -1);
    }
}
