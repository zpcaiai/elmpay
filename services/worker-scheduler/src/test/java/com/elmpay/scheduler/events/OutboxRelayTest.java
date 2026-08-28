package com.elmpay.scheduler.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class OutboxRelayTest {
    private static final UUID TENANT = UUID.fromString("12000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("12000000-0000-0000-0000-000000000002");
    private static final UUID EVENT = UUID.fromString("12000000-0000-0000-0000-000000000003");
    private static final UUID AGGREGATE = UUID.fromString("12000000-0000-0000-0000-000000000004");
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");

    @Test
    void publisherAckIsRequiredBeforePublishedMarker() {
        List<String> order = new ArrayList<>();
        FakeStore store = new FakeStore(order);
        OutboxRelay relay = relay(store, message -> order.add("publisher-ack"));

        assertEquals(OutboxRelay.Outcome.PUBLISHED, relay.runOnce(TENANT, "worker-a", NOW));
        assertEquals(List.of("claim", "publisher-ack", "mark-published"), order);
        assertEquals(1, store.marked);
        assertEquals(0, store.failures);
    }

    @Test
    void publisherFailureSchedulesBoundedRetryWithoutPublishedMarker() {
        FakeStore store = new FakeStore(new ArrayList<>());
        OutboxRelay relay = relay(store, message -> {
            throw new BrokerUnavailableException();
        });

        assertEquals(OutboxRelay.Outcome.RETRY_SCHEDULED,
                relay.runOnce(TENANT, "worker-a", NOW));
        assertEquals(0, store.marked);
        assertEquals(1, store.failures);
        assertEquals("BrokerUnavailableException", store.failureCode);
        assertEquals(Duration.ofSeconds(1), store.retryDelay);
    }

    @Test
    void crashAfterPublishIsRetryable() {
        FakeStore store = new FakeStore(new ArrayList<>());
        store.crashBeforeFirstMarker = true;
        AtomicInteger publications = new AtomicInteger();
        OutboxRelay relay = relay(store, message -> publications.incrementAndGet());

        assertThrows(SimulatedProcessCrash.class,
                () -> relay.runOnce(TENANT, "worker-a", NOW));
        assertEquals(OutboxRelay.Outcome.PUBLISHED,
                relay.runOnce(TENANT, "worker-b", NOW.plusSeconds(31)));
        assertEquals(2, publications.get(), "at-least-once relay must permit a duplicate");
        assertEquals(1, store.marked);
    }

    @Test
    void exponentialBackoffIsCapped() {
        OutboxRelay relay = relay(new FakeStore(new ArrayList<>()), message -> { });
        assertEquals(Duration.ofSeconds(1), relay.backoff(1));
        assertEquals(Duration.ofMinutes(15), relay.backoff(30));
    }

    @Test
    void productionSettingsAreExplicitAndFailClosed() {
        EventDeliverySettings settings = EventDeliverySettings.from(Map.of(
                EventDeliverySettings.OUTBOX_LEASE_TTL, "PT30S",
                EventDeliverySettings.PUBLISHER_BASE_BACKOFF, "PT1S",
                EventDeliverySettings.INBOX_LEASE_TTL, "PT2M",
                EventDeliverySettings.INBOX_RETRY_DELAY, "PT10S"));
        assertEquals(Duration.ofSeconds(30), settings.outboxLeaseTtl());
        assertEquals(Duration.ofMinutes(2), settings.inboxLeaseTtl());
        assertThrows(IllegalStateException.class,
                () -> EventDeliverySettings.from(Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new EventDeliverySettings(Duration.ZERO, Duration.ofSeconds(1),
                        Duration.ofSeconds(1), Duration.ofSeconds(1)));
    }

    private static OutboxRelay relay(FakeStore store, OutboxRelay.Publisher publisher) {
        return new OutboxRelay(store, publisher, Duration.ofSeconds(30), Duration.ofSeconds(1));
    }

    private static OutboxRelay.Message message(String owner, int attempt) {
        return new OutboxRelay.Message(1, EVENT, TENANT, PROJECT, "payment_intent", AGGREGATE,
                "payment.intent.updated.v1", 1, "{\"state\":\"authorized\"}",
                "correlation-b12", NOW, attempt, owner, attempt);
    }

    private static final class FakeStore implements OutboxRelay.Store {
        private final List<String> order;
        private int claims;
        private int marked;
        private int failures;
        private boolean published;
        private boolean crashBeforeFirstMarker;
        private Duration retryDelay;
        private String failureCode;

        private FakeStore(List<String> order) {
            this.order = order;
        }

        @Override
        public Optional<OutboxRelay.Message> claim(UUID tenantId, String workerId, Instant now,
                Duration leaseTtl) {
            order.add("claim");
            if (published) {
                return Optional.empty();
            }
            claims++;
            return Optional.of(message(workerId, claims));
        }

        @Override
        public void markPublished(OutboxRelay.Message message, Instant acknowledgedAt) {
            if (crashBeforeFirstMarker) {
                crashBeforeFirstMarker = false;
                throw new SimulatedProcessCrash();
            }
            order.add("mark-published");
            published = true;
            marked++;
        }

        @Override
        public void recordFailure(OutboxRelay.Message message, Instant failedAt,
                Duration nextDelay, String nextFailureCode) {
            order.add("record-failure");
            failures++;
            retryDelay = nextDelay;
            failureCode = nextFailureCode;
        }
    }

    private static final class BrokerUnavailableException extends Exception {
        @java.io.Serial
        private static final long serialVersionUID = 1L;
    }

    private static final class SimulatedProcessCrash extends Error {
        @java.io.Serial
        private static final long serialVersionUID = 1L;
    }
}
