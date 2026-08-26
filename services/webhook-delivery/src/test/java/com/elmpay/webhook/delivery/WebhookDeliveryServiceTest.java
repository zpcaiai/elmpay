package com.elmpay.webhook.delivery;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

final class WebhookDeliveryServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static final byte[] SECRET = "delivery-signing-secret-32-bytes!".getBytes(StandardCharsets.UTF_8);

    @Test
    void signsAndMarksSuccessfulDelivery() throws Exception {
        FakeOutbox outbox = new FakeOutbox(delivery(0, 3));
        AtomicReference<java.net.http.HttpRequest> sent = new AtomicReference<>();
        WebhookDeliveryService service = service(outbox, request -> {
            sent.set(request);
            return new WebhookDeliveryService.HttpResult(204, Map.of());
        }, InetAddress.getByName("8.8.8.8"));

        assertEquals(WebhookDeliveryService.Outcome.DELIVERED, service.deliverNext());
        assertEquals("DELIVERED", outbox.state);
        String timestamp = sent.get().headers().firstValue("X-Elmpay-Timestamp").orElseThrow();
        String supplied = sent.get().headers().firstValue("X-Elmpay-Signature").orElseThrow();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
        byte[] expected = mac.doFinal((timestamp + ".{\"event\":true}").getBytes(StandardCharsets.UTF_8));
        assertEquals("v1=" + Base64.getEncoder().encodeToString(expected), supplied);
    }

    @Test
    void retryableFailureIsScheduledThenExhaustionMovesToDeadLetter() throws Exception {
        FakeOutbox retry = new FakeOutbox(delivery(0, 3));
        WebhookDeliveryService retryService = service(retry,
                request -> new WebhookDeliveryService.HttpResult(503, Map.of()),
                InetAddress.getByName("8.8.8.8"));
        assertEquals(WebhookDeliveryService.Outcome.RETRY_SCHEDULED, retryService.deliverNext());
        assertEquals("RETRY", retry.state);
        assertTrue(retry.nextAttemptAt.isAfter(NOW));

        FakeOutbox exhausted = new FakeOutbox(delivery(2, 3));
        WebhookDeliveryService exhaustedService = service(exhausted,
                request -> new WebhookDeliveryService.HttpResult(503, Map.of()),
                InetAddress.getByName("8.8.8.8"));
        assertEquals(WebhookDeliveryService.Outcome.DEAD_LETTERED, exhaustedService.deliverNext());
        assertEquals("DEAD", exhausted.state);
    }

    @Test
    void blocksDnsRebindingToLoopbackBeforeNetworkCall() throws Exception {
        FakeOutbox outbox = new FakeOutbox(delivery(0, 3));
        AtomicInteger calls = new AtomicInteger();
        WebhookDeliveryService service = service(outbox, request -> {
            calls.incrementAndGet();
            return new WebhookDeliveryService.HttpResult(204, Map.of());
        }, InetAddress.getByName("127.0.0.1"));
        assertEquals(WebhookDeliveryService.Outcome.DEAD_LETTERED, service.deliverNext());
        assertEquals(0, calls.get());
        assertEquals("SECURITY_POLICY", outbox.errorCode);
    }

    @Test
    void keyRotationRequiresAnOverlap() {
        WebhookDeliveryService.RotatingKeyRing ring = keyRing();
        WebhookDeliveryService.SigningKey next = new WebhookDeliveryService.SigningKey("key-new",
                "delivery-next-signing-secret-32!!".getBytes(StandardCharsets.UTF_8),
                NOW.minusSeconds(60), NOW.plusSeconds(600));
        assertThrows(IllegalArgumentException.class, () -> ring.rotate(List.of(next)));
        ring.rotate(List.of(activeKey(), next));
        ring.rotate(List.of(next));
        assertEquals("key-new", ring.current(NOW).keyId());
    }

    private static WebhookDeliveryService service(FakeOutbox outbox,
            WebhookDeliveryService.Transport transport, InetAddress resolved) {
        WebhookDeliveryService.EndpointPolicy policy = new WebhookDeliveryService.EndpointPolicy(
                Set.of("hooks.example.test"), host -> new InetAddress[] {resolved});
        return new WebhookDeliveryService("tenant-001", outbox, transport, policy, keyRing(),
                Duration.ofSeconds(2), Duration.ofSeconds(30), Duration.ofSeconds(5),
                Duration.ofMinutes(10), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static WebhookDeliveryService.RotatingKeyRing keyRing() {
        return new WebhookDeliveryService.RotatingKeyRing(List.of(activeKey()));
    }

    private static WebhookDeliveryService.SigningKey activeKey() {
        return new WebhookDeliveryService.SigningKey("key-old", SECRET,
                NOW.minusSeconds(600), NOW.plusSeconds(600));
    }

    private static WebhookDeliveryService.Delivery delivery(int attempt, int maximum) {
        return new WebhookDeliveryService.Delivery(1, "tenant-001", "project-001", "endpoint-001",
                URI.create("https://hooks.example.test/payments"), "evt-001", "payment.succeeded",
                "{\"event\":true}".getBytes(StandardCharsets.UTF_8), attempt, maximum);
    }

    private static final class FakeOutbox implements WebhookDeliveryService.Outbox {
        private WebhookDeliveryService.Delivery pending;
        private String state = "PENDING";
        private String errorCode = "";
        private Instant nextAttemptAt = Instant.EPOCH;

        private FakeOutbox(WebhookDeliveryService.Delivery pending) {
            this.pending = pending;
        }

        @Override
        public Optional<WebhookDeliveryService.Delivery> claim(String tenantId, Instant now,
                Instant leaseUntil) {
            WebhookDeliveryService.Delivery result = pending;
            pending = null;
            state = result == null ? state : "IN_FLIGHT";
            return Optional.ofNullable(result);
        }

        @Override
        public void markDelivered(String tenantId, long deliveryId, int statusCode, Instant deliveredAt) {
            state = "DELIVERED";
        }

        @Override
        public void reschedule(String tenantId, long deliveryId, int statusCode, String failure,
                Instant next) {
            state = "RETRY";
            errorCode = failure;
            nextAttemptAt = next;
        }

        @Override
        public void deadLetter(String tenantId, long deliveryId, int statusCode, String failure,
                Instant failedAt) {
            state = "DEAD";
            errorCode = failure;
        }
    }
}
