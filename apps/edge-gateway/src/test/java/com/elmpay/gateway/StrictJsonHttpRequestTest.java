package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class StrictJsonHttpRequestTest {
    @Test
    void financialQueryParsingRejectsAmbiguityAndUnknownRouteFields() {
        assertEquals(Map.of("from", "2026-08-01T00:00:00Z", "to",
                "2026-08-02T00:00:00Z"), FinancialHttpHandler.query(
                        "from=2026-08-01T00%3A00%3A00Z&to=2026-08-02T00%3A00%3A00Z"));
        assertThrows(IllegalArgumentException.class,
                () -> FinancialHttpHandler.query("limit=10&limit=20"));
        assertThrows(IllegalArgumentException.class,
                () -> FinancialHttpHandler.query("limit=10&"));
        assertThrows(IllegalArgumentException.class,
                () -> FinancialHttpHandler.query("from=2026-08-01+00%3A00%3A00Z"));
        assertThrows(IllegalArgumentException.class,
                () -> FinancialHttpHandler.query("from=%FF"));
        assertThrows(IllegalArgumentException.class,
                () -> FinancialHttpHandler.requireOnlyQueryFields(Map.of("debug", "true"),
                        Set.of("from", "to")));
    }

    @Test
    void adminDiagnosticQueryRequiresCanonicalExactFields() {
        assertEquals(Map.of("tenantId", "30000000-0000-0000-0000-000000000001",
                "service", "risk-engine"), AdminActionHttpHandler.query(
                        "tenantId=30000000-0000-0000-0000-000000000001&service=risk-engine"));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionHttpHandler.query("%74enantId=x&service=risk-engine"));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionHttpHandler.query("tenantId=x&service=risk-engine&"));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionHttpHandler.query("tenantId=x&service=risk+engine"));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionHttpHandler.query("service=a&service=b"));
    }

    @Test
    void paymentTimelineQueryRejectsEmptyDuplicateAndUnknownSelectors() {
        assertEquals(new PaymentHttpHandler.TimelineQuery(0, 100),
                PaymentHttpHandler.timelineQuery(null));
        assertEquals(new PaymentHttpHandler.TimelineQuery(9, 25),
                PaymentHttpHandler.timelineQuery("after_sequence=9&limit=25"));
        assertThrows(IllegalArgumentException.class,
                () -> PaymentHttpHandler.timelineQuery(""));
        assertThrows(IllegalArgumentException.class,
                () -> PaymentHttpHandler.timelineQuery("limit=10&limit=20"));
        assertThrows(IllegalArgumentException.class,
                () -> PaymentHttpHandler.timelineQuery("debug=1"));
    }

    @Test
    void acceptsOnlyCanonicalExactStrictJsonRequests() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/strict", exchange -> {
            try (exchange) {
                try {
                    StrictJsonHttpRequest.validateEnvelope(exchange);
                    StrictJsonHttpRequest.body(exchange, 128, Set.of("value"));
                    exchange.sendResponseHeaders(204, -1);
                } catch (IllegalArgumentException invalid) {
                    exchange.sendResponseHeaders(400, -1);
                }
            }
        });
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try (HttpClient client = HttpClient.newHttpClient()) {
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/strict");
            assertEquals(204, send(client, HttpRequest.newBuilder(endpoint)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"value\":1}"))));
            assertEquals(400, send(client, HttpRequest.newBuilder(endpoint)
                    .header("Content-Type", "application/jsonx")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"value\":1}"))));
            assertEquals(400, send(client, HttpRequest.newBuilder(endpoint)
                    .header("Content-Type", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"value\":1}"))));
            assertEquals(400, send(client, HttpRequest.newBuilder(endpoint)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(
                            new byte[] {'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':',
                                    '"', (byte) 0xc3, '(', '"', '}'}))));
            URI nonCanonical = URI.create(endpoint + "//child");
            assertEquals(400, send(client, HttpRequest.newBuilder(nonCanonical)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"value\":1}"))));
        } finally {
            server.stop(0);
        }
    }

    private static int send(HttpClient client, HttpRequest.Builder request) throws Exception {
        return client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray()).statusCode();
    }
}
