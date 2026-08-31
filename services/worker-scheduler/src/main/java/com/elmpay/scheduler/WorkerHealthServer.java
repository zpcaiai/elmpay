package com.elmpay.scheduler;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Dedicated Kubernetes health listener; it exposes no mutation or tenant data. */
public final class WorkerHealthServer implements AutoCloseable {
    private final WorkerSchedulerRuntime runtime;
    private final HttpServer server;
    private final ExecutorService executor;

    public WorkerHealthServer(WorkerSchedulerRuntime runtime, String host, int port)
            throws IOException {
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/health/startup", exchange -> probe(exchange,
                runtime.startupHealthy(), "startup"));
        server.createContext("/health/live", exchange -> probe(exchange, runtime.live(), "live"));
        server.createContext("/health/ready", exchange -> probe(exchange, runtime.ready(),
                "ready"));
        executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "elmpay-worker-health");
            thread.setDaemon(true);
            return thread;
        });
        server.setExecutor(executor);
    }

    public void start() {
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(1);
        executor.shutdownNow();
    }

    private void probe(HttpExchange exchange, boolean healthy, String probe) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                response(exchange, 405, "{\"status\":\"method_not_allowed\"}");
                return;
            }
            String body = body(healthy, probe);
            response(exchange, healthy ? 200 : 503, body);
        } finally {
            exchange.close();
        }
    }

    private String body(boolean healthy, String probe) {
        WorkerSchedulerRuntime.CycleResult result = runtime.lastResult();
        Instant lastSuccess = runtime.lastSuccessfulCycle();
        return "{\"status\":\"" + (healthy ? "ok" : "unavailable") + "\","
                + "\"probe\":\"" + probe + "\","
                + "\"last_successful_cycle\":" + quoted(lastSuccess) + ","
                + "\"cycle_failures\":" + runtime.totalFailures() + ","
                + "\"last_cycle_failed_stages\":" + (result == null ? "null"
                        : Integer.toString(result.failures())) + "}";
    }

    private static String quoted(Instant value) {
        return value == null ? "null" : "\"" + value + "\"";
    }

    private static void response(HttpExchange exchange, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
