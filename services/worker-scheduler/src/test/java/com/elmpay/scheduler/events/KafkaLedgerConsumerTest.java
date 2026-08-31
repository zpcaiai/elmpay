package com.elmpay.scheduler.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.events.EventEnvelope;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.MockConsumer;
import org.apache.kafka.clients.consumer.OffsetResetStrategy;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
final class KafkaLedgerConsumerTest {
    private static final String TOPIC = "payment-events-v1";
    private static final TopicPartition PARTITION = new TopicPartition(TOPIC, 0);
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void commitsOnlyAfterAppliedDatabaseEffect() {
        MockConsumer<String, String> kafka = kafka(record(0));
        AtomicInteger effects = new AtomicInteger();
        KafkaLedgerConsumer consumer = consumer(kafka, (message, worker, now) -> {
            effects.incrementAndGet();
            return JdbcEventDeliveryStore.InboxOutcome.APPLIED;
        });

        assertEquals(KafkaLedgerConsumer.PollOutcome.PROCESSED, consumer.pollOnce());
        assertEquals(1, effects.get());
        assertEquals(1L, kafka.committed(Set.of(PARTITION)).get(PARTITION).offset());
        consumer.close();
    }

    @Test
    void busyEffectRewindsAndDoesNotCommitOffset() {
        MockConsumer<String, String> kafka = kafka(record(0));
        KafkaLedgerConsumer consumer = consumer(kafka, (message, worker, now) ->
                JdbcEventDeliveryStore.InboxOutcome.BUSY);

        consumer.pollOnce();
        assertEquals(0L, kafka.position(PARTITION));
        assertNull(kafka.committed(Set.of(PARTITION)).get(PARTITION));
        consumer.close();
    }

    @Test
    void duplicateOrTamperedHeadersRewindWithoutCommit() {
        ConsumerRecord<String, String> record = record(0);
        record.headers().add("elmpay-event-id", "duplicate".getBytes(StandardCharsets.UTF_8));
        MockConsumer<String, String> kafka = kafka(record);
        KafkaLedgerConsumer consumer = consumer(kafka, (message, worker, now) ->
                JdbcEventDeliveryStore.InboxOutcome.APPLIED);
        assertThrows(IllegalArgumentException.class, consumer::pollOnce);
        assertEquals(0L, kafka.position(PARTITION));
        consumer.close();
    }

    private static KafkaLedgerConsumer consumer(MockConsumer<String, String> kafka,
            KafkaLedgerConsumer.EventProcessor processor) {
        return new KafkaLedgerConsumer(kafka, processor, TOPIC, "worker-a",
                Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMillis(100));
    }

    private static MockConsumer<String, String> kafka(ConsumerRecord<String, String> record) {
        MockConsumer<String, String> kafka = new MockConsumer<>(OffsetResetStrategy.EARLIEST);
        kafka.schedulePollTask(() -> {
            kafka.rebalance(List.of(PARTITION));
            kafka.updateBeginningOffsets(Map.of(PARTITION, 0L));
            kafka.addRecord(record);
        });
        return kafka;
    }

    private static ConsumerRecord<String, String> record(long offset) {
        UUID event = UUID.fromString("20000000-0000-0000-0000-000000000001");
        UUID tenant = UUID.fromString("20000000-0000-0000-0000-000000000002");
        UUID project = UUID.fromString("20000000-0000-0000-0000-000000000003");
        UUID aggregate = UUID.fromString("20000000-0000-0000-0000-000000000004");
        EventEnvelope envelope = new EventEnvelope(event, "payment_intent.captured", 1,
                tenant, project, "payment_intent", aggregate, 1, NOW, NOW, "trace-1",
                Map.of("aggregate_revision", 1L, "amount_minor", 125L,
                        "business_order_digest", "a".repeat(64), "captured_at", NOW.toString(),
                        "currency", "USD", "payment_intent_id", aggregate.toString(),
                        "project_id", project.toString(), "provider", "stripe"));
        ConsumerRecord<String, String> record = new ConsumerRecord<>(TOPIC, 0, offset,
                envelope.aggregateKey(), envelope.canonicalJson());
        header(record, "elmpay-event-id", event.toString());
        header(record, "elmpay-event-name", envelope.eventName());
        header(record, "elmpay-event-version", "1");
        header(record, "elmpay-tenant-id", tenant.toString());
        header(record, "elmpay-project-id", project.toString());
        header(record, "elmpay-aggregate-type", "payment_intent");
        header(record, "elmpay-aggregate-id", aggregate.toString());
        header(record, "elmpay-aggregate-revision", "1");
        header(record, "elmpay-occurred-at", NOW.toString());
        header(record, "elmpay-recorded-at", NOW.toString());
        header(record, "elmpay-trace-id", "trace-1");
        return record;
    }

    private static void header(ConsumerRecord<String, String> record, String name, String value) {
        record.headers().add(name, value.getBytes(StandardCharsets.UTF_8));
    }
}
