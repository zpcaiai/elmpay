package com.elmpay.gateway;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;

public final class PaymentGatewayApplication {
    private PaymentGatewayApplication() {
    }

    public static void main(String[] args) throws IOException {
        Map<String, String> environment = System.getenv();
        RuntimeComponents runtime = RuntimeFactory.create(environment);
        int port = Integer.parseInt(environment.getOrDefault("PORT", "8080"));
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("PORT is outside the valid range");
        }
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 128);
        server.createContext("/", new PaymentHttpHandler(runtime,
                CheckoutRuntimeFactory.create(runtime.payments(), runtime.mode(), environment)));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(
                Math.toIntExact(Duration.ofSeconds(15).toSeconds())), "gateway-shutdown"));
        server.start();
    }
}
