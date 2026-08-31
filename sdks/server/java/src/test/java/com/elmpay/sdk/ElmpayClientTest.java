package com.elmpay.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

class ElmpayClientTest {
    private static final String PROJECT = "10000000-0000-4000-8000-000000000002";
    private static final String SESSION = "{\"checkout_session_id\":\"cs_123\","
            + "\"expires_at\":\"2026-08-30T12:00:00Z\","
            + "\"checkout_url\":\"https://checkout.example/cs_123\"}";

    @Test void rejectsUnboundedTimeout() {
        assertThrows(IllegalArgumentException.class,
                () -> new ElmpayClient(URI.create("https://api.example/"), "token", PROJECT,
                        Duration.ZERO, 1, (request, timeout) -> raw(200, "application/json", SESSION)));
        assertThrows(IllegalArgumentException.class,
                () -> new ElmpayClient(URI.create("https://api.example/"), "token", PROJECT,
                        Duration.ofMinutes(5).plusNanos(1), 1,
                        (request, timeout) -> raw(200, "application/json", SESSION)));
        assertThrows(IllegalArgumentException.class,
                () -> new ElmpayClient(URI.create("https://user:pass@api.example/"), "token", PROJECT,
                        Duration.ofSeconds(1), 1,
                        (request, timeout) -> raw(200, "application/json", SESSION)));
    }

    @Test void serializesCanonicalCheckoutRequestsAndDecodesTypedResponse() throws Exception {
        List<ElmpayClient.SdkRequest> calls = new ArrayList<>();
        var client = new ElmpayClient(URI.create("https://api.example/"), "token", PROJECT,
                Duration.ofSeconds(1), 1, (request, timeout) -> {
                    calls.add(request);
                    int status = request.method().equals("POST")
                            && request.uri().getRawPath().equals("/v1/checkout-sessions") ? 201 : 200;
                    return raw(status, "application/json", SESSION);
                });
        var created = client.createCheckoutSession(
                new ElmpayClient.CheckoutRequest("order-1", 1250, "USD", "complete"),
                "create-idempotency-0001");
        client.getCheckoutSession("session/unsafe");
        client.confirmCheckoutSession("session-1",
                new ElmpayClient.ConfirmRequest("stripe_card", "psp://tok/1", "fp"),
                "confirm-idempotency-001");
        assertEquals(201, created.statusCode());
        assertEquals("cs_123", created.data().checkoutSessionId());
        assertEquals(List.of("/v1/checkout-sessions", "/v1/checkout-sessions/session%2Funsafe",
                "/v1/checkout-sessions/session-1/confirm"),
                calls.stream().map(v -> v.uri().getRawPath()).toList());
        calls.forEach(v -> assertEquals(PROJECT, v.headers().get("x-project-id")));
        String create = calls.get(0).body();
        assertEquals("{\"business_order_no\":\"order-1\",\"amount\":1250,\"currency\":\"USD\",\"return_route_id\":\"complete\"}", create);
        assertFalse(create.contains("project_id"));
        assertFalse(create.contains("order_reference"));
        assertFalse(create.contains("amount_minor"));
        assertFalse(create.contains("return_uri"));
        assertEquals("{\"payment_method_type\":\"stripe_card\",\"payment_method_reference\":\"psp://tok/1\",\"fingerprint\":\"fp\"}",
                calls.get(2).body());
    }

    @Test void rejectsChunkedResponseOverUniformLimit() {
        byte[] oversized = new byte[ElmpayClient.MAX_RESPONSE_BYTES + 1];
        var client = client((request, timeout) -> new ElmpayClient.RawResponse(200,
                "application/json", -1, "request-1", new ByteArrayInputStream(oversized)));
        var error = assertThrows(ElmpayClient.ResponseTooLargeException.class,
                () -> client.getCheckoutSession("cs_123"));
        assertEquals("request-1", error.requestId());
    }

    @Test void rejectsContentTypeStatusAndTypedSchemaDrift() {
        assertThrows(ElmpayClient.InvalidResponseException.class,
                () -> client((request, timeout) -> raw(200, "text/html", SESSION))
                        .getCheckoutSession("cs_123"));
        assertThrows(ElmpayClient.InvalidResponseException.class,
                () -> client((request, timeout) -> raw(200, "application/json",
                        "{\"checkout_session_id\":\"cs_123\"}"))
                        .getCheckoutSession("cs_123"));
        assertThrows(ElmpayClient.InvalidResponseException.class,
                () -> client((request, timeout) -> raw(200, "application/json", SESSION))
                        .createCheckoutSession(new ElmpayClient.CheckoutRequest(
                                "order-1", 100, "USD", null), "idem-1"));
    }

    @Test void mapsProblemDetailsAndBindsHttpStatus() {
        String problem = "{\"type\":\"https://docs.example/problems/declined\","
                + "\"title\":\"Declined\",\"status\":402,"
                + "\"code\":\"payment_declined\",\"trace_id\":\"trace-1\"}";
        var error = assertThrows(ElmpayClient.ApiException.class,
                () -> client((request, timeout) -> raw(402, "application/problem+json", problem))
                        .getCheckoutSession("cs_123"));
        assertEquals(402, error.statusCode());
        assertEquals("payment_declined", error.problem().code());
        assertEquals("request-1", error.requestId());

        String mismatched = problem.replace("\"status\":402", "\"status\":400");
        assertThrows(ElmpayClient.InvalidResponseException.class,
                () -> client((request, timeout) -> raw(402, "application/problem+json", mismatched))
                        .getCheckoutSession("cs_123"));
    }

    @Test void verifiesFreshRawWebhookBytes() throws Exception {
        byte[] secret = Base64.getUrlDecoder().decode(
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc");
        byte[] body = "{\"event\":\"payment.succeeded\",\"amount\":1250}"
                .getBytes(StandardCharsets.UTF_8);
        long timestamp = 1787702400L;
        String header = "t=1787702400,v1=NgtUFKuSvOfNdb2InZjDTBS3axZlxKNnw1QLrb3elDw";
        var clock = Clock.fixed(Instant.ofEpochSecond(timestamp), ZoneOffset.UTC);
        assertTrue(ElmpayClient.verifyWebhook(secret, body, header, clock,
                Duration.ofMinutes(5)));
        assertFalse(ElmpayClient.verifyWebhook(secret,
                "{}".getBytes(StandardCharsets.UTF_8), header, clock, Duration.ofMinutes(5)));
        assertFalse(ElmpayClient.verifyWebhook(secret, body, header + ",t=" + timestamp,
                clock, Duration.ofMinutes(5)));
        assertFalse(ElmpayClient.verifyWebhook(secret, body, header + ",v1=bad",
                clock, Duration.ofMinutes(5)));
        assertFalse(ElmpayClient.verifyWebhook(secret, body, header.replace("t=", "t=+"),
                clock, Duration.ofMinutes(5)));
    }

    private static ElmpayClient client(ElmpayClient.Transport transport) {
        return new ElmpayClient(URI.create("https://api.example/"), "token", PROJECT,
                Duration.ofSeconds(1), 1, transport);
    }

    private static ElmpayClient.RawResponse raw(int status, String contentType, String body) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return new ElmpayClient.RawResponse(status, contentType, bytes.length, "request-1",
                new ByteArrayInputStream(bytes));
    }
}
