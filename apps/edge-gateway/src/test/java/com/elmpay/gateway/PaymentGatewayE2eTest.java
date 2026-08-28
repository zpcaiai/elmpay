package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class PaymentGatewayE2eTest {
    private static final String KEY = "local-api-secret-for-tests";
    private static final UUID TENANT = UUID.fromString("20000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("20000000-0000-0000-0000-000000000003");

    @Test
    void createsAndConfirmsAnIntentThroughTheHttpBoundary() throws Exception {
        String principals = ApiKeyAuthenticator.digestForProvisioning(KEY)
                + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT;
        RuntimeComponents runtime = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox",
                "ELMPAY_API_PRINCIPALS", principals));
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 16);
        server.createContext("/", new PaymentHttpHandler(runtime));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> created = client.send(request(base.resolve("/v1/payment_intents"),
                    "create-idempotency-0001", """
                    {"external_reference":"order-http-1","amount_minor":1250,"currency":"USD",
                     "allowed_methods":["card"],"confirmation_mode":"automatic",
                     "region":"US","ttl_minutes":60}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());
            String intentId = String.valueOf(Json.object(created.body()).get("id"));

            HttpResponse<String> confirmed = client.send(request(
                    base.resolve("/v1/payment_intents/" + intentId + "/confirm"),
                    "confirm-idempotency-0001", """
                    {"method":"card","payment_method_reference":"psp://local/reference-1",
                     "fingerprint":"fp-local","approved_return_route_id":"checkout-complete",
                     "provider_parameters":{"simulation":"succeeded"}}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, confirmed.statusCode(), confirmed.body());
            Map<String, Object> confirmation = Json.object(confirmed.body());
            @SuppressWarnings("unchecked")
            Map<String, Object> intent = (Map<String, Object>) confirmation.get("payment_intent");
            assertEquals("captured", intent.get("state"));
            assertEquals(1_250L, intent.get("captured_amount_minor"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void partialCaptureCloseIsExposedAndIdempotentAtTheHttpBoundary() throws Exception {
        String principals = ApiKeyAuthenticator.digestForProvisioning(KEY)
                + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT;
        RuntimeComponents runtime = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox",
                "ELMPAY_API_PRINCIPALS", principals));
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 16);
        server.createContext("/", new PaymentHttpHandler(runtime));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> created = client.send(request(base.resolve("/v1/payment-intents"),
                    "close-create-idempotency-0001", """
                    {"external_reference":"order-http-close","amount_minor":1000,"currency":"USD",
                     "allowed_methods":["card"],"confirmation_mode":"manual_capture",
                     "region":"US","ttl_minutes":60}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());
            String intentId = String.valueOf(Json.object(created.body()).get("id"));

            HttpResponse<String> authorized = client.send(request(
                    base.resolve("/v1/payment-intents/" + intentId + "/confirm"),
                    "close-confirm-idempotency-0001", """
                    {"method":"card","payment_method_reference":"psp://local/close-reference",
                     "fingerprint":"fp-close","provider_parameters":{"simulation":"authorized"}}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, authorized.statusCode(), authorized.body());

            HttpResponse<String> partial = client.send(request(
                    base.resolve("/v1/payment-intents/" + intentId + "/capture"),
                    "close-capture-idempotency-0001", "{\"amount_minor\":400}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, partial.statusCode(), partial.body());

            URI closeUri = base.resolve("/v1/payment-intents/" + intentId + "/close");
            HttpResponse<String> closed = client.send(request(closeUri,
                    "close-action-idempotency-0001", "{\"reason\":\"partial_fulfillment\"}"),
                    HttpResponse.BodyHandlers.ofString());
            HttpResponse<String> replay = client.send(request(closeUri,
                    "close-action-idempotency-0001", "{\"reason\":\"partial_fulfillment\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, closed.statusCode(), closed.body());
            assertEquals(200, replay.statusCode(), replay.body());
            @SuppressWarnings("unchecked")
            Map<String, Object> closedIntent = (Map<String, Object>)
                    Json.object(closed.body()).get("payment_intent");
            assertEquals("captured", closedIntent.get("state"));
            assertEquals(400L, closedIntent.get("captured_amount_minor"));
            assertEquals(true, Json.object(replay.body()).get("replayed"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void canonicalAndBrowserCheckoutRoutesShareOneSignedServerAuthoritativeSession()
            throws Exception {
        String principals = ApiKeyAuthenticator.digestForProvisioning(KEY)
                + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT;
        RuntimeComponents runtime = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox",
                "ELMPAY_API_PRINCIPALS", principals));
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 16);
        server.createContext("/", new PaymentHttpHandler(runtime));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> created = client.send(checkoutRequest(
                    base.resolve("/v1/checkout-sessions"), "POST", KEY,
                    "checkout-create-00000001", """
                    {"business_order_no":"checkout-order-1","amount":1250,"currency":"USD",
                     "return_route_id":"checkout-complete"}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());
            Map<String, Object> createdBody = Json.object(created.body());
            String sessionId = String.valueOf(createdBody.get("checkout_session_id"));
            URI checkoutUrl = URI.create(String.valueOf(createdBody.get("checkout_url")));
            assertNull(checkoutUrl.getQuery(), "the checkout bearer must never enter an HTTP query");
            assertFalse(checkoutUrl.getRawPath().contains("token"));
            Map<String, String> fragment = fragment(checkoutUrl.getRawFragment());
            assertEquals(sessionId, fragment.get("session"));
            String token = fragment.get("token");
            assertTrue(token.matches("[A-Za-z0-9_-]{48}\\.[A-Za-z0-9_-]{43}"));

            HttpResponse<String> canonical = client.send(checkoutRequest(
                    base.resolve("/v1/checkout-sessions/" + sessionId), "GET", KEY,
                    null, null), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, canonical.statusCode(), canonical.body());
            assertEquals("OPEN", Json.object(canonical.body()).get("status"));

            HttpResponse<String> missingToken = client.send(browserRequest(
                    base.resolve("/api/checkout/sessions/" + sessionId), "GET", null,
                    null, null), HttpResponse.BodyHandlers.ofString());
            assertEquals(401, missingToken.statusCode(), missingToken.body());
            HttpResponse<String> invalidToken = client.send(browserRequest(
                    base.resolve("/api/checkout/sessions/" + sessionId), "GET",
                    "M".repeat(48) + "." + "A".repeat(43), null, null),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(401, invalidToken.statusCode(), invalidToken.body());

            HttpResponse<String> browserOpen = client.send(browserRequest(
                    base.resolve("/api/checkout/sessions/" + sessionId), "GET", token,
                    null, null), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, browserOpen.statusCode(), browserOpen.body());
            assertEquals("OPEN", Json.object(browserOpen.body()).get("status"));

            HttpResponse<String> confirmed = client.send(browserRequest(
                    base.resolve("/api/checkout/sessions/" + sessionId + "/confirm"), "POST",
                    token, "checkout-confirm-0000001", "{\"method\":\"card\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, confirmed.statusCode(), confirmed.body());
            assertEquals("SUCCEEDED", Json.object(confirmed.body()).get("status"));

            HttpResponse<String> verified = client.send(checkoutRequest(
                    base.resolve("/v1/checkout-sessions/" + sessionId), "GET", KEY,
                    null, null), HttpResponse.BodyHandlers.ofString());
            assertEquals("SUCCEEDED", Json.object(verified.body()).get("status"));

            HttpResponse<String> floatingAmount = client.send(checkoutRequest(
                    base.resolve("/v1/checkout-sessions"), "POST", KEY,
                    "checkout-create-00000002",
                    "{\"business_order_no\":\"o2\",\"amount\":1.5,\"currency\":\"USD\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, floatingAmount.statusCode(), floatingAmount.body());
            HttpResponse<String> rawRedirect = client.send(checkoutRequest(
                    base.resolve("/v1/checkout-sessions"), "POST", KEY,
                    "checkout-create-00000003",
                    "{\"business_order_no\":\"o3\",\"amount\":1,\"currency\":\"USD\",\"return_url\":\"https://evil.example\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, rawRedirect.statusCode(), rawRedirect.body());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void refundRouteUsesCapturedPaymentAndReturnsDurableProviderState() throws Exception {
        String principals = ApiKeyAuthenticator.digestForProvisioning(KEY)
                + "|test|" + TENANT + "|" + PROJECT + "|" + MERCHANT;
        RuntimeComponents runtime = RuntimeFactory.create(Map.of(
                "ELMPAY_RUNTIME_MODE", "local",
                "ELMPAY_ENABLE_LOCAL_SANDBOX", "true",
                "ELMPAY_LOCAL_RISK_POLICY", "approve-sandbox",
                "ELMPAY_API_PRINCIPALS", principals));
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 16);
        server.createContext("/", new PaymentHttpHandler(runtime));
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        try {
            URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> created = client.send(request(base.resolve("/v1/payment-intents"),
                    "refund-payment-create", """
                    {"external_reference":"refund-order-1","amount_minor":1250,"currency":"USD",
                     "allowed_methods":["card"],"confirmation_mode":"automatic",
                     "region":"US","ttl_minutes":60}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());
            String intentId = String.valueOf(Json.object(created.body()).get("id"));
            HttpResponse<String> confirmed = client.send(request(
                    base.resolve("/v1/payment-intents/" + intentId + "/confirm"),
                    "refund-payment-confirm", """
                    {"method":"card","payment_method_reference":"psp://local/refund",
                     "fingerprint":"fp-refund","provider_parameters":{"simulation":"succeeded"}}
                    """), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, confirmed.statusCode(), confirmed.body());

            HttpResponse<String> refund = client.send(refundRequest(
                    base.resolve("/v1/refunds"), "POST", "refund-create-route-1",
                    "{" + "\"payment_intent_id\":\"" + intentId
                            + "\",\"amount\":1250,\"reason\":\"customer_request\"}"),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, refund.statusCode(), refund.body());
            Map<String, Object> refundBody = Json.object(refund.body());
            assertEquals("succeeded", refundBody.get("status"));
            assertEquals(1250L, refundBody.get("amount"));

            HttpResponse<String> replay = client.send(refundRequest(
                    base.resolve("/v1/refunds/" + refundBody.get("id")), "GET", null, null),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, replay.statusCode(), replay.body());
            assertEquals(refundBody.get("id"), Json.object(replay.body()).get("id"));
        } finally {
            server.stop(0);
        }
    }

    private static HttpRequest request(URI uri, String idempotencyKey, String body) {
        return HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + KEY)
                .header("X-Project-Id", PROJECT.toString())
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", idempotencyKey)
                .header("X-Request-Id", "request-http-0001")
                .header("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static HttpRequest checkoutRequest(URI uri, String method, String token,
            String idempotencyKey, String body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + token)
                .header("X-Project-Id", PROJECT.toString())
                .header("X-Request-Id", "request-checkout-0001")
                .header("traceparent",
                        "00-33333333333333333333333333333333-4444444444444444-01");
        if (idempotencyKey != null) {
            builder.header("Idempotency-Key", idempotencyKey);
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        return builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static HttpRequest refundRequest(URI uri, String method, String idempotencyKey,
            String body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Authorization", "Bearer " + KEY)
                .header("X-Project-Id", PROJECT.toString())
                .header("X-Device-Context-Digest", "a".repeat(64))
                .header("X-Request-Id", "request-refund-0001")
                .header("traceparent",
                        "00-55555555555555555555555555555555-6666666666666666-01");
        if (idempotencyKey != null) {
            builder.header("Idempotency-Key", idempotencyKey);
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        return builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static HttpRequest browserRequest(URI uri, String method, String token,
            String idempotencyKey, String body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("X-Request-Id", "request-browser-0001")
                .header("traceparent",
                        "00-55555555555555555555555555555555-6666666666666666-01");
        if (token != null) {
            builder.header("Authorization", "CheckoutSession " + token);
        }
        if (idempotencyKey != null) {
            builder.header("Idempotency-Key", idempotencyKey);
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        return builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static Map<String, String> fragment(String rawFragment) {
        Map<String, String> result = new java.util.HashMap<>();
        for (String item : rawFragment.split("&")) {
            String[] pair = item.split("=", 2);
            result.put(pair[0], java.net.URLDecoder.decode(pair[1],
                    java.nio.charset.StandardCharsets.UTF_8));
        }
        return result;
    }
}
