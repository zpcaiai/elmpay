package com.elmpay.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Probe-only listener. It intentionally exposes no business route or authentication surface. */
public final class GatewayHealthHandler implements HttpHandler {
    private final RuntimeComponents runtime;

    public GatewayHealthHandler(RuntimeComponents runtime) {
        this.runtime = java.util.Objects.requireNonNull(runtime, "runtime");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                respond(exchange, 405, Map.of("status", "method_not_allowed"));
                return;
            }
            String path = exchange.getRequestURI().getPath();
            if (exchange.getRequestURI().getRawQuery() != null) {
                respond(exchange, 404, Map.of("status", "not_found"));
            } else if ("/health/startup".equals(path)) {
                respond(exchange, 200, Map.of("status", "started", "mode", runtime.mode()));
            } else if ("/health/live".equals(path)) {
                respond(exchange, 200, Map.of("status", "live", "mode", runtime.mode()));
            } else if ("/health/ready".equals(path)) {
                respond(exchange, runtime.ready() ? 200 : 503,
                        Map.of("status", runtime.ready() ? "ready" : "not_ready",
                                "mode", runtime.mode()));
            } else {
                respond(exchange, 404, Map.of("status", "not_found"));
            }
        } finally {
            exchange.close();
        }
    }

    private static void respond(HttpExchange exchange, int status, Map<String, ?> value)
            throws IOException {
        byte[] body = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }
}
