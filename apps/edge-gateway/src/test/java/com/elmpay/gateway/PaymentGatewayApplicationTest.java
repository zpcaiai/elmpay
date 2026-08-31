package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.elmpay.webhook.ingress.WebhookIngressRuntime;
import com.elmpay.webhook.ingress.WebhookIngressService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

final class PaymentGatewayApplicationTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void registersReachableProductionWebhookPath() throws Exception {
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (context, headers, body, receivedAt) -> new WebhookIngressService.VerifiedEvent(
                        "evt-edge", "payment.succeeded", "pi-edge", "order-edge", receivedAt,
                        "key-edge", "{\"verified\":true}".getBytes(StandardCharsets.UTF_8))),
                (context, event, digest) -> true);
        WebhookIngressRuntime runtime = new WebhookIngressRuntime(token -> Optional.of(
                new WebhookIngressRuntime.EndpointBinding("tenant-edge", "project-edge",
                        "stripe", "account-edge")), service);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        PaymentGatewayApplication.registerProviderWebhookRoute(server, runtime,
                Clock.fixed(NOW, ZoneOffset.UTC));
        server.start();
        try {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/v1/provider-webhooks/" + "a".repeat(32));
            HttpResponse<Void> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(), HttpResponse.BodyHandlers.discarding());
            assertEquals(202, response.statusCode());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void healthListenerHasNoBusinessCapability() throws Exception {
        String tenant = "61000000-0000-4000-8000-000000000001";
        String project = "61000000-0000-4000-8000-000000000002";
        String merchant = "61000000-0000-4000-8000-000000000003";
        RuntimeComponents components = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local", "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox", "ELMPAY_API_PRINCIPALS",
                ApiKeyAuthenticator.digestForProvisioning("health-listener-placeholder")
                        + "|health|" + tenant + "|" + project + "|" + merchant));
        HttpServer health = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        health.createContext("/", new GatewayHealthHandler(components));
        health.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + health.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> live = client.send(HttpRequest.newBuilder(
                    base.resolve("/health/live")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, live.statusCode());
            HttpResponse<String> business = client.send(HttpRequest.newBuilder(
                    base.resolve("/v1/payment_intents")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(404, business.statusCode());
            assertFalse(business.body().contains("payment"));
        } finally {
            health.stop(0);
        }
    }
}
