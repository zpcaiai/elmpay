package com.elmpay.scheduler.events;

import com.elmpay.events.EventEnvelope;
import com.elmpay.events.StrictJson;
import com.elmpay.scheduler.FileBackedPostgresDataSource;
import com.elmpay.scheduler.WorkerSchedulerSettings;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.serialization.StringSerializer;

/** TLS-authenticated Kafka publisher that returns only after an all-replicas ACK. */
public final class KafkaOutboxPublisher implements OutboxRelay.Publisher, AutoCloseable {
    private static final int MAXIMUM_PAYLOAD_BYTES = 1_048_576;

    private final Producer<String, String> producer;
    private final String topic;
    private final Duration acknowledgementTimeout;

    public KafkaOutboxPublisher(WorkerSchedulerSettings settings) {
        this(new KafkaProducer<>(properties(Objects.requireNonNull(settings, "settings"))),
                settings.kafkaTopic(), settings.kafkaAcknowledgementTimeout());
    }

    KafkaOutboxPublisher(Producer<String, String> producer, String topic,
            Duration acknowledgementTimeout) {
        this.producer = Objects.requireNonNull(producer, "producer");
        this.topic = Objects.requireNonNull(topic, "topic");
        this.acknowledgementTimeout = Objects.requireNonNull(acknowledgementTimeout,
                "acknowledgementTimeout");
    }

    @Override
    public void publish(OutboxRelay.Message message) throws Exception {
        Objects.requireNonNull(message, "message");
        EventEnvelope envelope = new EventEnvelope(message.eventId(), message.eventName(),
                message.eventVersion(), message.tenantId(), message.projectId(),
                message.aggregateType(), message.aggregateId(), message.aggregateRevision(),
                message.occurredAt(), message.recordedAt(), message.traceId(),
                StrictJson.object(message.payloadJson()));
        String envelopeJson = envelope.canonicalJson();
        byte[] payload = envelopeJson.getBytes(StandardCharsets.UTF_8);
        if (payload.length > MAXIMUM_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("outbox event exceeds the governed Kafka limit");
        }
        RecordHeaders headers = new RecordHeaders();
        header(headers, "elmpay-event-id", message.eventId().toString());
        header(headers, "elmpay-event-name", message.eventName());
        header(headers, "elmpay-event-version", Integer.toString(message.eventVersion()));
        header(headers, "elmpay-tenant-id", message.tenantId().toString());
        header(headers, "elmpay-project-id", message.projectId().toString());
        header(headers, "elmpay-aggregate-type", message.aggregateType());
        header(headers, "elmpay-aggregate-id", message.aggregateId().toString());
        header(headers, "elmpay-aggregate-revision",
                Long.toString(message.aggregateRevision()));
        header(headers, "elmpay-occurred-at", message.occurredAt().toString());
        header(headers, "elmpay-recorded-at", message.recordedAt().toString());
        header(headers, "elmpay-trace-id", message.traceId());
        String key = envelope.aggregateKey();
        ProducerRecord<String, String> record = new ProducerRecord<>(topic, null,
                message.occurredAt().toEpochMilli(), key, envelopeJson, headers);
        RecordMetadata metadata;
        try {
            metadata = producer.send(record).get(acknowledgementTimeout.toMillis(),
                    TimeUnit.MILLISECONDS);
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw failure;
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IllegalStateException("Kafka publication failed", cause);
        } catch (TimeoutException failure) {
            throw new IllegalStateException("Kafka acknowledgement deadline exceeded", failure);
        }
        if (!topic.equals(metadata.topic()) || metadata.partition() < 0 || metadata.offset() < 0) {
            throw new IllegalStateException("Kafka returned an invalid acknowledgement");
        }
    }

    @Override
    public void close() {
        producer.close(Duration.ofSeconds(10));
    }

    static Properties properties(WorkerSchedulerSettings settings) {
        requireRegular(settings.kafkaTruststoreFile(), "Kafka truststore");
        requireRegular(settings.kafkaKeystoreFile(), "Kafka keystore");
        Properties properties = new Properties();
        properties.setProperty(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,
                settings.kafkaBootstrapServers());
        properties.setProperty(ProducerConfig.CLIENT_ID_CONFIG, settings.kafkaClientId());
        properties.setProperty(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,
                StringSerializer.class.getName());
        properties.setProperty(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,
                StringSerializer.class.getName());
        properties.setProperty(ProducerConfig.ACKS_CONFIG, "all");
        properties.setProperty(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        properties.setProperty(ProducerConfig.RETRIES_CONFIG, Integer.toString(Integer.MAX_VALUE));
        properties.setProperty(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, "5");
        properties.setProperty(ProducerConfig.MAX_REQUEST_SIZE_CONFIG,
                Integer.toString(MAXIMUM_PAYLOAD_BYTES));
        properties.setProperty("allow.auto.create.topics", "false");
        properties.setProperty(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG,
                Long.toString(settings.kafkaAcknowledgementTimeout().toMillis()));
        properties.setProperty(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG,
                Long.toString(settings.kafkaAcknowledgementTimeout().plusSeconds(1).toMillis()));
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

    private static void header(RecordHeaders headers, String name, String value) {
        headers.add(name, value.getBytes(StandardCharsets.UTF_8));
    }
}
