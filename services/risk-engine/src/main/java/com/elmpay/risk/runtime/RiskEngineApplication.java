package com.elmpay.risk.runtime;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.RiskEngine;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Independent production risk process with mTLS business and isolated health listeners. */
public final class RiskEngineApplication {
    private RiskEngineApplication() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("risk runtime accepts no CLI args");
        configureHttpBounds();
        Map<String, String> environment = System.getenv();
        Clock clock = Clock.systemUTC();
        RiskRuntimeConfig config = RiskRuntimeConfig.fromEnvironment(environment);
        RiskPostgresDataSource database = RiskPostgresDataSource.fromEnvironment(environment);
        RiskRuntimeSchemaVerifier schema = new RiskRuntimeSchemaVerifier(database);
        schema.verify();
        StrictHttpsTransport signalTransport = new StrictHttpsTransport(
                RiskTlsContexts.client(environment, "ELMPAY_RISK_SIGNAL_", clock),
                config.dependencyTimeout(), 128 * 1024);
        StrictHttpsTransport modelTransport = new StrictHttpsTransport(
                RiskTlsContexts.client(environment, "ELMPAY_RISK_MODEL_", clock),
                config.dependencyTimeout(), 128 * 1024);
        SignalProvider signals = HttpsRiskDependencies.signal(config.signalEndpoint(),
                config.signalReadiness(), signalTransport, clock);
        ModelProvider models = HttpsRiskDependencies.model(config.modelEndpoint(),
                config.modelReadiness(), modelTransport, clock);
        RiskEngine engine = new RiskEngine(clock, config.maximumSignalAge(),
                config.modelReviewThreshold(), config.modelBlockThreshold());
        JdbcRiskDecisionService decisions = new JdbcRiskDecisionService(database, signals, models,
                engine, clock, config.nonceTtl());
        JdbcRiskControlPlane controls = new JdbcRiskControlPlane(database, clock,
                config.governancePolicyDigest(), Duration.ofMinutes(30),
                config.adminActionPolicyDigest(), config.adminActionPolicyValidUntil());
        AdminRiskActionCommandConsumer adminCommands = new AdminRiskActionCommandConsumer(
                database, controls, clock, config.adminWorkerId(), config.adminCommandLease(),
                config.adminCommandPollInterval(), config.adminActionPolicyValidUntil());

        ExecutorService businessExecutor = Executors.newVirtualThreadPerTaskExecutor();
        ExecutorService healthExecutor = Executors.newFixedThreadPool(2);
        HttpsServer business = HttpsServer.create(config.businessAddress(), 128);
        RiskTlsContexts.server(environment, clock).configure(business);
        business.createContext("/", new RiskHttpApi(decisions, controls, config.callerPolicy(), clock));
        business.setExecutor(businessExecutor);

        HttpServer health = HttpServer.create(config.healthAddress(), 16);
        health.createContext("/health/startup", exchange -> health(exchange, 200, "started"));
        health.createContext("/health/live", exchange -> health(exchange, 200, "live"));
        health.createContext("/health/ready", exchange -> {
            boolean ready = schema.ready() && decisions.ready() && adminCommands.ready();
            health(exchange, ready ? 200 : 503, ready ? "ready" : "not_ready");
        });
        health.setExecutor(healthExecutor);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            adminCommands.close();
            business.stop(1);
            health.stop(1);
            businessExecutor.close();
            healthExecutor.close();
        }, "risk-runtime-shutdown"));
        adminCommands.start();
        business.start();
        health.start();
        new CountDownLatch(1).await();
    }

    private static void configureHttpBounds() {
        System.setProperty("sun.net.httpserver.maxReqTime", "5");
        System.setProperty("sun.net.httpserver.maxRspTime", "5");
        System.setProperty("sun.net.httpserver.maxReqHeaders", "32");
        System.setProperty("sun.net.httpserver.maxReqHeaderSize", "16384");
    }

    private static void health(HttpExchange exchange, int status, String state) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "GET");
                status = 405;
                state = "method_not_allowed";
            }
            byte[] body = StrictJson.canonical(Map.of("status", state))
                    .getBytes(StandardCharsets.UTF_8);
            try {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Cache-Control", "no-store");
                exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
                exchange.sendResponseHeaders(status, body.length);
                exchange.getResponseBody().write(body);
            } finally {
                java.util.Arrays.fill(body, (byte) 0);
            }
        } finally {
            exchange.close();
        }
    }
}
