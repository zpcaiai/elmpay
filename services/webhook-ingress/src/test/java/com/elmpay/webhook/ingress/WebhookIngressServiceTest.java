package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class WebhookIngressServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");

    @Test
    void verifiesBeforeDurableWriteAndAcknowledgesDuplicates() {
        AtomicInteger verificationCalls = new AtomicInteger();
        Set<String> inbox = new HashSet<>();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (merchant, headers, body, receivedAt) -> {
                    verificationCalls.incrementAndGet();
                    if (!"valid".equals(headers.get("signature"))) {
                        throw new SecurityException("bad signature");
                    }
                    return event("evt-001", receivedAt);
                }), (context, event, body, digest) -> inbox.add(event.providerEventId()));

        WebhookIngressService.Receipt first = service.ingest(context(), Map.of("signature", "valid"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));
        WebhookIngressService.Receipt duplicate = service.ingest(context(), Map.of("signature", "valid"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));

        assertEquals(WebhookIngressService.Outcome.ACCEPTED, first.outcome());
        assertEquals(WebhookIngressService.Outcome.DUPLICATE, duplicate.outcome());
        assertEquals(2, verificationCalls.get());
        assertEquals(1, inbox.size());
    }

    @Test
    void badSignatureCannotReachInbox() {
        AtomicInteger writes = new AtomicInteger();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (merchant, headers, body, receivedAt) -> {
                    throw new SecurityException("bad signature");
                }), (context, event, body, digest) -> {
                    writes.incrementAndGet();
                    return true;
                });
        assertThrows(SecurityException.class, () -> service.ingest(context(), Map.of(),
                "{}".getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, writes.get());
    }

    @Test
    void preservesOutOfOrderVerifiedFactsForAsynchronousStateMachine() {
        Set<String> stored = new HashSet<>();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (merchant, headers, body, receivedAt) -> event(headers.get("event"),
                        Instant.parse(headers.get("occurred")))),
                (context, event, body, digest) -> stored.add(event.providerEventId()));
        WebhookIngressService.Receipt recent = service.ingest(context(),
                Map.of("event", "evt-recent", "occurred", "2026-08-26T00:00:10Z"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));
        WebhookIngressService.Receipt older = service.ingest(context(),
                Map.of("event", "evt-older", "occurred", "2026-08-26T00:00:05Z"),
                "{\"safe\":true}".getBytes(StandardCharsets.UTF_8));
        assertEquals(WebhookIngressService.Outcome.ACCEPTED, recent.outcome());
        assertEquals(WebhookIngressService.Outcome.ACCEPTED, older.outcome());
        assertEquals(Set.of("evt-recent", "evt-older"), stored);
    }

    @Test
    void rejectsCardFieldsBeforeVerificationOrPersistence() {
        AtomicInteger verifierCalls = new AtomicInteger();
        WebhookIngressService service = new WebhookIngressService(Map.of("stripe",
                (merchant, headers, body, receivedAt) -> {
                    verifierCalls.incrementAndGet();
                    return event("evt-001", receivedAt);
                }), (context, event, body, digest) -> true);
        assertThrows(SecurityException.class, () -> service.ingest(context(), Map.of(),
                "{\"card_number\":\"4242424242424242\"}".getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, verifierCalls.get());
    }

    private static WebhookIngressService.Context context() {
        return new WebhookIngressService.Context("tenant-001", "project-001", "stripe",
                "merchant-001", NOW);
    }

    private static WebhookIngressService.VerifiedEvent event(String id, Instant occurredAt) {
        return new WebhookIngressService.VerifiedEvent(id, "payment.succeeded", "pi-001",
                "order-001", occurredAt, "key-001", "{\"verified\":true}".getBytes(StandardCharsets.UTF_8));
    }
}
