package com.elmpay.scheduler.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.events.EventEnvelope;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class WebhookFanoutPublisherTest {
    private static final Instant NOW = Instant.parse("2026-09-08T00:00:00Z");
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000101");
    private static final UUID PROJECT = UUID.fromString("00000000-0000-0000-0000-000000000202");

    @Test
    void fansCanonicalEnvelopeToEveryEndpointBeforeBrokerPublication() throws Exception {
        List<String> calls = new ArrayList<>();
        List<String> payloads = new ArrayList<>();
        WebhookFanoutPublisher publisher = new WebhookFanoutPublisher(
                (tenantId, projectId) -> List.of("endpoint-a", "endpoint-b"),
                (tenantId, projectId, endpointId, eventId, eventType, payload, now) -> {
                    calls.add("webhook:" + endpointId);
                    payloads.add(new String(payload, StandardCharsets.UTF_8));
                    return true;
                },
                message -> calls.add("broker"), Clock.fixed(NOW, ZoneOffset.UTC));

        OutboxRelay.Message message = message();
        publisher.publish(message);

        assertEquals(List.of("webhook:endpoint-a", "webhook:endpoint-b", "broker"), calls);
        assertEquals(2, payloads.size());
        EventEnvelope first = EventEnvelope.parse(payloads.getFirst());
        assertEquals(message.eventId(), first.eventId());
        assertEquals(message.eventName(), first.eventName());
        assertEquals(message.tenantId(), first.tenantId());
        assertEquals(message.projectId(), first.projectId());
        assertEquals(payloads.getFirst(), payloads.getLast());
    }

    @Test
    void webhookFailurePreventsBrokerAcknowledgement() {
        List<String> calls = new ArrayList<>();
        WebhookFanoutPublisher publisher = new WebhookFanoutPublisher(
                (tenantId, projectId) -> List.of("endpoint-a"),
                (tenantId, projectId, endpointId, eventId, eventType, payload, now) -> {
                    throw new IllegalStateException("outbox unavailable");
                },
                message -> calls.add("broker"), Clock.fixed(NOW, ZoneOffset.UTC));

        assertThrows(IllegalStateException.class, () -> publisher.publish(message()));
        assertEquals(List.of(), calls);
    }

    private static OutboxRelay.Message message() {
        return new OutboxRelay.Message(1, UUID.fromString(
                "00000000-0000-0000-0000-000000000303"), TENANT, PROJECT,
                "payment_intent", UUID.fromString("00000000-0000-0000-0000-000000000404"),
                2, "payment_intent.captured", 1,
                "{\"amount_minor\":9900,\"currency\":\"CNY\"}", NOW.minusSeconds(1), NOW,
                "trace-elmos-1", 1, "worker-1", 1);
    }
}
