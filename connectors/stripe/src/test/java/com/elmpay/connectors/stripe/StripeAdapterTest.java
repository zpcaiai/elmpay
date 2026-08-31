package com.elmpay.connectors.stripe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.WebhookRequest;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class StripeAdapterTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static final byte[] SECRET = "whsec_fixture_secret_32_bytes_long"
            .getBytes(StandardCharsets.UTF_8);

    @Test
    void validatesRawBodySignatureAndDetectsOutOfOrderEvents() throws Exception {
        StripeAdapter adapter = adapter(request -> new StripeAdapter.HttpResult(200, "{}".getBytes(StandardCharsets.UTF_8)));
        byte[] recent = event("evt_recent", 200);
        StripeAdapter.VerifiedWebhook first = adapter.verifyWebhook(signature(recent), recent, NOW,
                expected(1250));
        assertFalse(first.outOfOrder());

        byte[] older = event("evt_older", 100);
        StripeAdapter.VerifiedWebhook second = adapter.verifyWebhook(signature(older), older, NOW,
                expected(1250));
        assertTrue(second.outOfOrder());
    }

    @Test
    void rejectsWrongSignatureAndAmountTampering() throws Exception {
        StripeAdapter adapter = adapter(request -> new StripeAdapter.HttpResult(200, new byte[0]));
        byte[] body = event("evt_fixture", 200);
        assertThrows(SecurityException.class,
                () -> adapter.verifyWebhook("t=" + NOW.getEpochSecond() + ",v1=" + "00".repeat(32),
                        body, NOW, expected(1250)));
        assertThrows(SecurityException.class,
                () -> adapter.verifyWebhook(signature(body), body, NOW, expected(1251)));
    }

    @Test
    void enforcesSecretRotationOverlap() {
        StripeAdapter adapter = adapter(request -> new StripeAdapter.HttpResult(200, new byte[0]));
        StripeAdapter.WebhookSecret next = new StripeAdapter.WebhookSecret("key-new",
                "another_webhook_secret_32_bytes!!".getBytes(StandardCharsets.UTF_8),
                NOW.minusSeconds(60), NOW.plusSeconds(600));
        assertThrows(IllegalArgumentException.class, () -> adapter.rotateWebhookSecrets(List.of(next)));
        adapter.rotateWebhookSecrets(List.of(activeSecret(), next));
        adapter.rotateWebhookSecrets(List.of(next));
    }

    @Test
    void rejectsPanAndReturnsUnknownAfterFiniteRetriesUsingStableStripeKey() {
        AtomicInteger calls = new AtomicInteger();
        List<String> keys = new ArrayList<>();
        StripeAdapter adapter = adapter(request -> {
            calls.incrementAndGet();
            keys.add(request.headers().firstValue("Idempotency-Key").orElseThrow());
            throw new IOException("synthetic timeout");
        });
        assertThrows(IllegalArgumentException.class, () -> adapter.submitDisputeEvidence("dp_fixture123",
                Map.of("customer_communication", "4242 4242 4242 4242"), "idem-stripe-00000001"));

        StripeAdapter.OperationResult result = adapter.createPaymentIntent(new StripeAdapter.PaymentRequest(
                1250, "USD", "pm_fixture123", false, "order-001", "idem-stripe-00000001"));
        assertEquals(StripeAdapter.State.UNKNOWN, result.state());
        assertEquals(2, calls.get());
        assertEquals(List.of("idem-stripe-00000001", "idem-stripe-00000001"), keys);
    }

    @Test
    void closesAndWipesEachTransportResponseAcrossRetryAndSuccess() {
        List<StripeAdapter.HttpResult> responses = new ArrayList<>();
        AtomicInteger calls = new AtomicInteger();
        StripeAdapter adapter = adapter(request -> {
            StripeAdapter.HttpResult response = calls.getAndIncrement() == 0
                    ? new StripeAdapter.HttpResult(503, "{}".getBytes(StandardCharsets.UTF_8))
                    : new StripeAdapter.HttpResult(200,
                            "{\"id\":\"pi_fixture123\",\"status\":\"succeeded\"}"
                                    .getBytes(StandardCharsets.UTF_8));
            responses.add(response);
            return response;
        });

        StripeAdapter.OperationResult result = adapter.createPaymentIntent(new StripeAdapter.PaymentRequest(
                1250, "USD", "pm_fixture123", false, "order-001", "idem-stripe-00000001"));

        assertEquals(StripeAdapter.State.SUCCEEDED, result.state());
        assertEquals(2, responses.size());
        responses.forEach(response -> {
            assertThrows(IllegalStateException.class, response::body);
            assertThrows(IllegalStateException.class, response::bodyLength);
        });
    }

    @Test
    void duplicateProviderResponseKeysFailToUnknown() {
        StripeAdapter adapter = adapter(request -> new StripeAdapter.HttpResult(200,
                ("{\"id\":\"pi_fixture123\",\"status\":\"succeeded\","
                        + "\"status\":\"failed\"}").getBytes(StandardCharsets.UTF_8)));

        StripeAdapter.OperationResult result = adapter.createPaymentIntent(
                new StripeAdapter.PaymentRequest(1250, "USD", "pm_fixture123", false,
                        "order-001", "idem-stripe-00000001"));

        assertEquals(StripeAdapter.State.UNKNOWN, result.state());
        assertFalse(result.finalState());
    }

    @Test
    void commonBridgeDelegatesToConcreteAdapterAndMissingConfigFailsClosed() {
        StripeProviderBridge bridge = new StripeProviderBridge(new StripeProviderBridge.Runtime(
                adapter(request -> new StripeAdapter.HttpResult(200,
                        "{\"id\":\"pi_fixture123\",\"status\":\"requires_action\"}"
                                .getBytes(StandardCharsets.UTF_8))),
                request -> expected(1250)));
        assertTrue(bridge.configured());
        assertEquals(ProviderOutcome.REQUIRES_ACTION, bridge.createPayment(command()).outcome());

        String previous = System.getProperty("elmpay.stripe.adapterFactory");
        System.clearProperty("elmpay.stripe.adapterFactory");
        try {
            StripeProviderBridge missing = new StripeProviderBridge();
            assertFalse(missing.configured());
            assertThrows(ProviderException.class, () -> missing.createPayment(command()));
        } finally {
            restore("elmpay.stripe.adapterFactory", previous);
        }
    }

    @Test
    void commonBridgeRejectsCaseVariantDuplicateSignatureHeaders() throws Exception {
        StripeProviderBridge bridge = new StripeProviderBridge(new StripeProviderBridge.Runtime(
                adapter(request -> new StripeAdapter.HttpResult(200,
                        "{}".getBytes(StandardCharsets.UTF_8))), request -> expected(1250)));
        byte[] body = event("evt_duplicate_header", 200);
        try (WebhookRequest request = new WebhookRequest(
                UUID.fromString("30000000-0000-0000-0000-000000000001"),
                UUID.fromString("30000000-0000-0000-0000-000000000002"),
                Map.of("Stripe-Signature", signature(body),
                        "stripe-signature", signature(body)), body, NOW)) {
            assertThrows(SecurityException.class, () -> bridge.verifyWebhook(request));
        }
    }

    private static CreatePaymentCommand command() {
        ProviderRequestContext context = new ProviderRequestContext(
                UUID.fromString("30000000-0000-0000-0000-000000000001"),
                UUID.fromString("30000000-0000-0000-0000-000000000002"),
                UUID.fromString("30000000-0000-0000-0000-000000000003"),
                "idem-stripe-00000001", "corr-stripe", "cred-v1");
        return new CreatePaymentCommand(context,
                UUID.fromString("30000000-0000-0000-0000-000000000004"), "order_123456",
                Money.of(1250, "USD"), "stripe_card", null,
                Map.of("payment_method_reference", "pm_fixture123"));
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }

    private static StripeAdapter adapter(StripeAdapter.Transport transport) {
        return new StripeAdapter(new StripeAdapter.Config(URI.create("https://api.stripe.com"),
                URI.create("https://checkout.example.test/"), () -> "sk_test_fixture", List.of(activeSecret()), Duration.ofSeconds(2),
                Duration.ofMinutes(5), 2, Clock.fixed(NOW, ZoneOffset.UTC)), transport);
    }

    private static StripeAdapter.WebhookSecret activeSecret() {
        return new StripeAdapter.WebhookSecret("key-old", SECRET,
                NOW.minusSeconds(600), NOW.plusSeconds(600));
    }

    private static StripeAdapter.ExpectedWebhook expected(long amount) {
        return new StripeAdapter.ExpectedWebhook("pi_fixture123", amount, "USD", "order_123456");
    }

    private static byte[] event(String eventId, long created) {
        String body = "{\"id\":\"" + eventId + "\",\"type\":\"payment_intent.succeeded\","
                + "\"created\":" + created + ",\"metadata\":{\"id\":\"pi_decoy123\"},"
                + "\"data\":{\"object\":{\"id\":\"pi_fixture123\","
                + "\"amount\":1250,\"currency\":\"usd\",\"status\":\"succeeded\"}}}";
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static String signature(byte[] body) throws Exception {
        String timestamp = Long.toString(NOW.getEpochSecond());
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
        mac.update(timestamp.getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) '.');
        byte[] digest = mac.doFinal(body);
        return "t=" + timestamp + ",v1=" + HexFormat.of().formatHex(digest);
    }
}
