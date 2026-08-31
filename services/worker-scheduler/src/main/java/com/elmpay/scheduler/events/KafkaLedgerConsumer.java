package com.elmpay.scheduler.events;

import com.elmpay.events.EventEnvelope;
import com.elmpay.scheduler.FileBackedPostgresDataSource;
import com.elmpay.scheduler.LedgerPostingConsumer;
import com.elmpay.scheduler.WorkerSchedulerSettings;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.serialization.StringDeserializer;

/** read_committed mTLS Kafka consumer with database-effect-before-offset semantics. */
public final class KafkaLedgerConsumer implements AutoCloseable {
    private static final int MAXIMUM_EVENT_BYTES = 1_048_576;
    private static final int MAXIMUM_HEADER_BYTES = 512;
    private static final Set<String> HEADERS = Set.of(
            "elmpay-event-id", "elmpay-event-name", "elmpay-event-version",
            "elmpay-tenant-id", "elmpay-project-id", "elmpay-aggregate-type",
            "elmpay-aggregate-id", "elmpay-aggregate-revision", "elmpay-occurred-at",
            "elmpay-recorded-at", "elmpay-trace-id");

    public enum PollOutcome {
        IDLE,
        PROCESSED
    }

    @FunctionalInterface
    interface EventProcessor {
        JdbcEventDeliveryStore.InboxOutcome consume(JdbcEventDeliveryStore.InboxMessage message,
                String workerId, java.time.Instant now);
    }

    private final Consumer<String, String> consumer;
    private final EventProcessor processor;
    private final String topic;
    private final String workerId;
    private final Clock clock;
    private final Duration pollTimeout;

    public KafkaLedgerConsumer(WorkerSchedulerSettings settings,
            LedgerPostingConsumer posting, Clock clock) {
        this(new KafkaConsumer<>(properties(settings)), posting::consume, settings.kafkaTopic(),
                settings.workerId(), clock, settings.kafkaConsumerPollTimeout());
    }

    KafkaLedgerConsumer(Consumer<String, String> consumer, EventProcessor processor,
            String topic, String workerId, Clock clock, Duration pollTimeout) {
        this.consumer = Objects.requireNonNull(consumer, "consumer");
        this.processor = Objects.requireNonNull(processor, "processor");
        this.topic = Objects.requireNonNull(topic, "topic");
        this.workerId = Objects.requireNonNull(workerId, "workerId");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.pollTimeout = Objects.requireNonNull(pollTimeout, "pollTimeout");
        consumer.subscribe(List.of(topic));
    }

    public PollOutcome pollOnce() {
        ConsumerRecords<String, String> batch = consumer.poll(pollTimeout);
        if (batch.isEmpty()) {
            return PollOutcome.IDLE;
        }
        List<ConsumerRecord<String, String>> records = new ArrayList<>();
        batch.forEach(records::add);
        for (int index = 0; index < records.size(); index++) {
            ConsumerRecord<String, String> record = records.get(index);
            try {
                EventEnvelope envelope = verifiedEnvelope(record);
                JdbcEventDeliveryStore.InboxOutcome outcome = processor.consume(
                        new JdbcEventDeliveryStore.InboxMessage(envelope.eventId(),
                                envelope.tenantId(), envelope.projectId(),
                                envelope.aggregateType(), envelope.aggregateId(),
                                envelope.revision(), envelope.eventName(), envelope.eventVersion(),
                                com.elmpay.events.StrictJson.canonical(envelope.payload()),
                                envelope.occurredAt(), envelope.recordedAt(), envelope.traceId()),
                        workerId, clock.instant());
                if (outcome == JdbcEventDeliveryStore.InboxOutcome.BUSY) {
                    rewind(records, index);
                    return PollOutcome.PROCESSED;
                }
                TopicPartition partition = new TopicPartition(record.topic(), record.partition());
                consumer.commitSync(Map.of(partition,
                        new OffsetAndMetadata(Math.addExact(record.offset(), 1))));
            } catch (RuntimeException failure) {
                rewind(records, index);
                throw failure;
            }
        }
        return PollOutcome.PROCESSED;
    }

    public boolean assigned() {
        return !consumer.assignment().isEmpty();
    }

    public void wakeup() {
        consumer.wakeup();
    }

    @Override
    public void close() {
        consumer.close();
    }

    private EventEnvelope verifiedEnvelope(ConsumerRecord<String, String> record) {
        if (!topic.equals(record.topic()) || record.key() == null || record.value() == null
                || record.value().getBytes(StandardCharsets.UTF_8).length > MAXIMUM_EVENT_BYTES) {
            throw new IllegalArgumentException("Kafka record violates topic, key or size policy");
        }
        Map<String, String> headers = headers(record);
        EventEnvelope envelope = EventEnvelope.parse(record.value());
        require(headers, "elmpay-event-id", envelope.eventId().toString());
        require(headers, "elmpay-event-name", envelope.eventName());
        require(headers, "elmpay-event-version", Integer.toString(envelope.eventVersion()));
        require(headers, "elmpay-tenant-id", envelope.tenantId().toString());
        require(headers, "elmpay-project-id", envelope.projectId().toString());
        require(headers, "elmpay-aggregate-type", envelope.aggregateType());
        require(headers, "elmpay-aggregate-id", envelope.aggregateId().toString());
        require(headers, "elmpay-aggregate-revision", Long.toString(envelope.revision()));
        require(headers, "elmpay-occurred-at", envelope.occurredAt().toString());
        require(headers, "elmpay-recorded-at", envelope.recordedAt().toString());
        require(headers, "elmpay-trace-id", envelope.traceId());
        if (!record.key().equals(envelope.aggregateKey())) {
            throw new SecurityException("Kafka key does not match the aggregate identity");
        }
        return envelope;
    }

    private static Map<String, String> headers(ConsumerRecord<String, String> record) {
        Map<String, String> values = new HashMap<>();
        Set<String> seen = new HashSet<>();
        for (Header header : record.headers()) {
            if (!HEADERS.contains(header.key()) || !seen.add(header.key())
                    || header.value() == null || header.value().length == 0
                    || header.value().length > MAXIMUM_HEADER_BYTES) {
                throw new IllegalArgumentException("Kafka headers are unknown, duplicate or invalid");
            }
            values.put(header.key(), utf8(header.value()));
        }
        if (!values.keySet().equals(HEADERS)) {
            throw new IllegalArgumentException("Kafka record is missing governed headers");
        }
        return values;
    }

    private static String utf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException failure) {
            throw new IllegalArgumentException("Kafka header is not valid UTF-8", failure);
        }
    }

    private static void require(Map<String, String> headers, String name, String expected) {
        if (!expected.equals(headers.get(name))) {
            throw new SecurityException("Kafka header does not match the signed envelope: " + name);
        }
    }

    private void rewind(List<ConsumerRecord<String, String>> records, int from) {
        Map<TopicPartition, Long> offsets = new HashMap<>();
        for (int index = from; index < records.size(); index++) {
            ConsumerRecord<String, String> record = records.get(index);
            TopicPartition partition = new TopicPartition(record.topic(), record.partition());
            offsets.merge(partition, record.offset(), Math::min);
        }
        offsets.forEach(consumer::seek);
    }

    static Properties properties(WorkerSchedulerSettings settings) {
        requireRegular(settings.kafkaTruststoreFile(), "Kafka truststore");
        requireRegular(settings.kafkaKeystoreFile(), "Kafka keystore");
        Properties properties = new Properties();
        properties.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,
                settings.kafkaBootstrapServers());
        properties.setProperty(ConsumerConfig.CLIENT_ID_CONFIG,
                settings.kafkaClientId() + "-ledger");
        properties.setProperty(ConsumerConfig.GROUP_ID_CONFIG, settings.kafkaConsumerGroupId());
        properties.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG,
                StringDeserializer.class.getName());
        properties.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG,
                StringDeserializer.class.getName());
        properties.setProperty(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false");
        properties.setProperty(ConsumerConfig.ISOLATION_LEVEL_CONFIG, "read_committed");
        properties.setProperty(ConsumerConfig.ALLOW_AUTO_CREATE_TOPICS_CONFIG, "false");
        properties.setProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        properties.setProperty(ConsumerConfig.MAX_POLL_RECORDS_CONFIG,
                Integer.toString(settings.kafkaConsumerMaxPollRecords()));
        properties.setProperty(ConsumerConfig.MAX_PARTITION_FETCH_BYTES_CONFIG,
                Integer.toString(MAXIMUM_EVENT_BYTES));
        properties.setProperty(ConsumerConfig.FETCH_MAX_BYTES_CONFIG,
                Integer.toString(MAXIMUM_EVENT_BYTES));
        properties.setProperty(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL");
        properties.setProperty(SslConfigs.SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG, "https");
        properties.setProperty(SslConfigs.SSL_PROTOCOL_CONFIG, "TLSv1.3");
        properties.setProperty(SslConfigs.SSL_ENABLED_PROTOCOLS_CONFIG, "TLSv1.3");
        properties.setProperty(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG, "PKCS12");
        properties.setProperty(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG,
                settings.kafkaTruststoreFile().toString());
        properties.setProperty(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG,
                secret(settings.kafkaTruststorePasswordFile(), "Kafka truststore password"));
        properties.setProperty(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PKCS12");
        properties.setProperty(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG,
                settings.kafkaKeystoreFile().toString());
        properties.setProperty(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG,
                secret(settings.kafkaKeystorePasswordFile(), "Kafka keystore password"));
        properties.setProperty(SslConfigs.SSL_KEY_PASSWORD_CONFIG,
                secret(settings.kafkaKeystorePasswordFile(), "Kafka key password"));
        return properties;
    }

    private static String secret(Path path, String label) {
        try {
            return FileBackedPostgresDataSource.mountedSecret(path);
        } catch (SQLException failure) {
            throw new IllegalStateException(label + " mount cannot be read", failure);
        }
    }

    private static void requireRegular(Path path, String label) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(label + " mount is not a regular file");
        }
    }
}
