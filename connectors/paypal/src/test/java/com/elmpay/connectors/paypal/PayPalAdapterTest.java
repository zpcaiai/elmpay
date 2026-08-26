package com.elmpay.connectors.paypal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderRequestContext;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class PayPalAdapterTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");

    @Test
    void delegatesWebhookSignatureDecisionToOfficialVerificationEndpointAndBindsMerchantAmount() {
        PayPalAdapter adapter = adapter(request -> {
            String path = request.uri().getPath();
            if (path.equals("/v1/oauth2/token")) {
                return json(200, "{\"access_token\":\"access-fixture\",\"expires_in\":3600}");
            }
            if (path.equals("/v1/notifications/verify-webhook-signature")) {
                return json(200, "{\"verification_status\":\"SUCCESS\"}");
            }
            throw new AssertionError("unexpected path: " + path);
        });

        PayPalAdapter.VerifiedWebhook event = adapter.verifyWebhook(headers(), event(),
                new PayPalAdapter.ExpectedWebhook("CAPTURE-123456", "MERCHANT123", 1250, "USD", 2));

        assertEquals("WH-EVENT-123456", event.eventId());
        assertEquals(1250, event.amountMinor());
    }

    @Test
    void rejectsOfficialVerificationFailureAndMerchantMismatch() {
        PayPalAdapter rejected = adapter(request -> request.uri().getPath().equals("/v1/oauth2/token")
                ? json(200, "{\"access_token\":\"access-fixture\",\"expires_in\":3600}")
                : json(200, "{\"verification_status\":\"FAILURE\"}"));
        assertThrows(SecurityException.class, () -> rejected.verifyWebhook(headers(), event(),
                new PayPalAdapter.ExpectedWebhook("CAPTURE-123456", "MERCHANT123", 1250, "USD", 2)));

        PayPalAdapter acceptedSignature = adapter(request -> request.uri().getPath().equals("/v1/oauth2/token")
                ? json(200, "{\"access_token\":\"access-fixture\",\"expires_in\":3600}")
                : json(200, "{\"verification_status\":\"SUCCESS\"}"));
        assertThrows(SecurityException.class, () -> acceptedSignature.verifyWebhook(headers(), event(),
                new PayPalAdapter.ExpectedWebhook("CAPTURE-123456", "OTHER-MERCHANT", 1250, "USD", 2)));
    }

    @Test
    void returnsUnknownAfterFiniteOrderTimeoutsWithStablePayPalRequestId() {
        AtomicInteger orderCalls = new AtomicInteger();
        List<String> requestIds = new ArrayList<>();
        PayPalAdapter adapter = adapter(request -> {
            if (request.uri().getPath().equals("/v1/oauth2/token")) {
                return json(200, "{\"access_token\":\"access-fixture\",\"expires_in\":3600}");
            }
            orderCalls.incrementAndGet();
            requestIds.add(request.headers().firstValue("PayPal-Request-Id").orElseThrow());
            throw new IOException("synthetic timeout");
        });
        PayPalAdapter.OperationResult result = adapter.createOrder(new PayPalAdapter.OrderRequest(
                "order-001", 1250, "USD", 2, false, "returnroute000001", "cancelroute000001",
                "idem-paypal-00000001"));
        assertEquals(PayPalAdapter.State.UNKNOWN, result.state());
        assertEquals(2, orderCalls.get());
        assertEquals(List.of("idem-paypal-00000001", "idem-paypal-00000001"), requestIds);
    }

    @Test
    void commonBridgeDelegatesToConcreteAdapterAndMissingConfigFailsClosed() {
        PayPalProviderBridge bridge = new PayPalProviderBridge(new PayPalProviderBridge.Runtime(
                adapter(request -> request.uri().getPath().equals("/v1/oauth2/token")
                        ? json(200, "{\"access_token\":\"access-fixture\",\"expires_in\":3600}")
                        : json(201, "{\"id\":\"O-FIXTURE123\",\"status\":\"CREATED\"}")),
                request -> new PayPalAdapter.ExpectedWebhook("CAPTURE-123456", "MERCHANT123",
                        1250, "USD", 2)));
        assertTrue(bridge.configured());
        assertEquals(ProviderOutcome.REQUIRES_ACTION, bridge.createPayment(command()).outcome());

        String previous = System.getProperty("elmpay.paypal.adapterFactory");
        System.clearProperty("elmpay.paypal.adapterFactory");
        try {
            PayPalProviderBridge missing = new PayPalProviderBridge();
            assertFalse(missing.configured());
            assertThrows(ProviderException.class, () -> missing.createPayment(command()));
        } finally {
            restore("elmpay.paypal.adapterFactory", previous);
        }
    }

    private static CreatePaymentCommand command() {
        ProviderRequestContext context = new ProviderRequestContext(
                UUID.fromString("40000000-0000-0000-0000-000000000001"),
                UUID.fromString("40000000-0000-0000-0000-000000000002"),
                UUID.fromString("40000000-0000-0000-0000-000000000003"),
                "idem-paypal-00000001", "corr-paypal", "cred-v1");
        return new CreatePaymentCommand(context,
                UUID.fromString("40000000-0000-0000-0000-000000000004"), "order_123456",
                Money.of(1250, "USD"), "paypal", "returnroute000001",
                Map.of("cancel_route_id", "cancelroute000001"));
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }

    private static PayPalAdapter adapter(PayPalAdapter.Transport transport) {
        return new PayPalAdapter(new PayPalAdapter.Config(URI.create("https://api-m.sandbox.paypal.com"),
                URI.create("https://checkout.example.test/"), "WH-ID-123456", Set.of("api-m.sandbox.paypal.com"),
                () -> new PayPalAdapter.ClientCredentials("client-fixture", "secret-fixture"),
                Duration.ofSeconds(2), 2, Clock.fixed(NOW, ZoneOffset.UTC)), transport);
    }

    private static Map<String, String> headers() {
        return Map.of(
                "PAYPAL-TRANSMISSION-ID", "transmission-001",
                "PAYPAL-TRANSMISSION-TIME", NOW.toString(),
                "PAYPAL-CERT-URL", "https://api-m.sandbox.paypal.com/certs/cert.pem",
                "PAYPAL-AUTH-ALGO", "SHA256withRSA",
                "PAYPAL-TRANSMISSION-SIG", "synthetic-signature");
    }

    private static byte[] event() {
        return ("{\"id\":\"WH-EVENT-123456\",\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\","
                + "\"resource\":{\"id\":\"CAPTURE-123456\",\"amount\":{\"value\":\"12.50\","
                + "\"currency_code\":\"USD\"},\"payee\":{\"merchant_id\":\"MERCHANT123\"}}}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static PayPalAdapter.HttpResult json(int status, String body) {
        return new PayPalAdapter.HttpResult(status, body.getBytes(StandardCharsets.UTF_8));
    }
}
