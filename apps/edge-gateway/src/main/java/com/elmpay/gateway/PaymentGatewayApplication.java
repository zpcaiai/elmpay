package com.elmpay.gateway;

import com.elmpay.webhook.ingress.WebhookIngressHttpHandler;
import com.elmpay.webhook.ingress.WebhookIngressRuntime;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;

public final class PaymentGatewayApplication {
    private PaymentGatewayApplication() {
    }

    public static void main(String[] args) throws IOException {
        Map<String, String> environment = System.getenv();
        RuntimeComponents runtime = RuntimeFactory.create(environment);
        int port = port(environment, "PORT", "postgres".equals(runtime.mode()) ? 8443 : 8080);
        int healthPort = port(environment, "ELMPAY_HEALTH_PORT",
                "postgres".equals(runtime.mode()) ? 8081 : 8090);
        if (port == healthPort) {
            throw new IllegalArgumentException("business and health ports must be different");
        }
        HttpServer server = businessServer(runtime.mode(), environment, port);
        HttpServer health = HttpServer.create(listenerAddress(runtime.mode(), healthPort), 16);
        health.createContext("/", new GatewayHealthHandler(runtime));
        CommerceHttpHandler commerce = new CommerceHttpHandler(runtime.authenticator(),
                CommerceRuntimeFactory.create(environment));
        server.createContext("/v1/billing", commerce);
        server.createContext("/v1/disputes", commerce);
        server.createContext("/v1/finance", new FinancialHttpHandler(runtime.authenticator(),
                FinancialRuntimeFactory.create(environment)));
        PaymentLinkHttpHandler paymentLinks = new PaymentLinkHttpHandler(runtime.authenticator(),
                PaymentLinkRuntimeFactory.create(environment));
        server.createContext("/v1/payment-links", paymentLinks);
        server.createContext("/api/payment-links/redeem", paymentLinks);
        registerProviderWebhookRoute(server, runtime.webhookIngress(), Clock.systemUTC());
        registerAdminActionRoutes(server, AdminActionRuntimeFactory.create(runtime.mode(),
                environment, Clock.systemUTC()));
        CheckoutRuntimeFactory.Runtime checkout = CheckoutRuntimeFactory.createRuntime(
                runtime.payments(), runtime.mode(), environment);
        server.createContext("/", new PaymentHttpHandler(runtime, checkout.checkout(),
                checkout.providerSdk()));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        health.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(Math.toIntExact(Duration.ofSeconds(15).toSeconds()));
            health.stop(Math.toIntExact(Duration.ofSeconds(5).toSeconds()));
            runtime.adminCommands().close();
        }, "gateway-shutdown"));
        if ("postgres".equals(runtime.mode())) {
            runtime.adminCommands().start();
        }
        server.start();
        health.start();
    }

    private static HttpServer businessServer(String mode, Map<String, String> environment, int port)
            throws IOException {
        InetSocketAddress address = listenerAddress(mode, port);
        if ("local".equals(mode)) {
            return HttpServer.create(address, 128);
        }
        HttpsServer server = HttpsServer.create(address, 128);
        GatewayTlsConfiguration.fromEnvironment(environment, Clock.systemUTC()).configure(server);
        return server;
    }

    static InetSocketAddress listenerAddress(String mode, int port) {
        return "local".equals(mode)
                ? new InetSocketAddress("127.0.0.1", port)
                : new InetSocketAddress(port);
    }

    private static int port(Map<String, String> environment, String name, int fallback) {
        int port;
        try {
            port = Integer.parseInt(environment.getOrDefault(name, Integer.toString(fallback)));
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(name + " is invalid", invalid);
        }
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException(name + " is outside the valid range");
        }
        return port;
    }

    static void registerProviderWebhookRoute(HttpServer server, WebhookIngressRuntime webhookIngress,
            Clock clock) {
        if (webhookIngress != null) {
            server.createContext(WebhookIngressHttpHandler.PATH_PREFIX,
                    new WebhookIngressHttpHandler(webhookIngress, clock));
        }
    }

    static void registerAdminActionRoutes(HttpServer server,
            java.util.Optional<AdminActionRuntimeFactory.Runtime> runtime) {
        if (runtime.isEmpty()) {
            return;
        }
        AdminActionHttpHandler handler = new AdminActionHttpHandler(runtime.orElseThrow());
        server.createContext(AdminActionHttpHandler.ACTIONS_PATH, handler);
        server.createContext(AdminActionHttpHandler.DIAGNOSTICS_PATH, handler);
        server.createContext(AdminActionHttpHandler.READY_PATH, handler);
    }
}
