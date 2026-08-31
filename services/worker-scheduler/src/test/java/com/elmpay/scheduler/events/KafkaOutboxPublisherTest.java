package com.elmpay.scheduler.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.scheduler.WorkerSchedulerSettings;
import com.elmpay.events.EventEnvelope;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;
import java.util.UUID;
import org.apache.kafka.clients.producer.MockProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class KafkaOutboxPublisherTest {
    @TempDir
    Path directory;

    @Test
    void publishesExactEventOnlyAfterBrokerAcknowledgement() throws Exception {
        MockProducer<String, String> producer = new MockProducer<String, String>(true, null,
                new StringSerializer(), new StringSerializer());
        KafkaOutboxPublisher publisher = new KafkaOutboxPublisher(producer,
                "payment.events.v1", Duration.ofSeconds(1));
        try {
            publisher.publish(message("{\"state\":\"captured\"}"));
            assertEquals(1, producer.history().size());
            var record = producer.history().getFirst();
            assertEquals("payment.events.v1", record.topic());
            EventEnvelope envelope = EventEnvelope.parse(record.value());
            assertEquals("captured", envelope.payload().get("state"));
            assertEquals(envelope.aggregateKey(), record.key());
            assertTrue(record.headers().lastHeader("elmpay-event-id") != null);
            assertTrue(record.headers().lastHeader("elmpay-tenant-id") != null);
            assertTrue(record.headers().lastHeader("elmpay-aggregate-revision") != null);
        } finally {
            publisher.close();
        }
    }

    @Test
    void brokerFailureAndOversizedPayloadNeverLookPublished() {
        MockProducer<String, String> producer = new MockProducer<String, String>(false, null,
                new StringSerializer(), new StringSerializer());
        producer.errorNext(new IllegalStateException("broker unavailable"));
        KafkaOutboxPublisher publisher = new KafkaOutboxPublisher(producer,
                "payment.events.v1", Duration.ofSeconds(1));
        assertThrows(IllegalStateException.class,
                () -> publisher.publish(message("{\"safe\":true}")));
        assertThrows(IllegalArgumentException.class,
                () -> publisher.publish(message("{\"x\":\""
                        + "x".repeat(1_048_577) + "\"}")));
        publisher.close();
    }

    @Test
    void producerPropertiesEnforceTlsMutualAuthAndAllReplicaAcks() throws Exception {
        WorkerSchedulerSettings settings = settings();
        Properties properties = KafkaOutboxPublisher.properties(settings);
        assertEquals("all", properties.getProperty(ProducerConfig.ACKS_CONFIG));
        assertEquals("true", properties.getProperty(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG));
        assertEquals("SSL", properties.getProperty("security.protocol"));
        assertEquals("TLSv1.3", properties.getProperty(SslConfigs.SSL_PROTOCOL_CONFIG));
        assertEquals("https",
                properties.getProperty(SslConfigs.SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG));
        assertEquals("PKCS12", properties.getProperty(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG));
        assertEquals("5", properties.getProperty(
                ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION));

        Files.delete(settings.kafkaTruststoreFile());
        assertThrows(IllegalStateException.class,
                () -> KafkaOutboxPublisher.properties(settings));
    }

    private WorkerSchedulerSettings settings() throws Exception {
        Path databasePassword = secret("db-password", "database-secret");
        Path databaseCa = secret("db-ca.crt", "certificate");
        Path databaseCertificate = secret("db-client.crt", "certificate");
        Path databasePrivateKey = secret("db-client.key", "private-key");
        Path adminPolicy = secret("admin-policy.json", """
                {"schemaVersion":1,"adminActionPolicyDigest":"%s",
                 "validUntil":"2026-09-30T00:00:00Z"}
                """.formatted("a".repeat(64)));
        Path truststore = secret("truststore.p12", "not-a-real-store");
        Path truststorePassword = secret("truststore-password", "trust-secret");
        Path keystore = secret("keystore.p12", "not-a-real-store");
        Path keystorePassword = secret("keystore-password", "key-secret");
        return new WorkerSchedulerSettings("worker-a",
                "jdbc:postgresql://db.internal:5432/elmpay", "elmpay_worker", databasePassword,
                databaseCa, databaseCertificate, databasePrivateKey, adminPolicy,
                Duration.ofSeconds(2), Duration.ofSeconds(30), 100, 5,
                Duration.ofSeconds(30), 50, 25, 20,
                java.util.List.of("stripe"), Duration.ofHours(2), 1, 100_000,
                Duration.ofMinutes(10), 6,
                "worker-scheduler", "scheduled-partition-maintenance", "127.0.0.1", 8081,
                "broker-1.internal:9093,broker-2.internal:9093", "payment.events.v1",
                "elmpay-worker-a", truststore, truststorePassword, keystore, keystorePassword,
                Duration.ofSeconds(5), "elmpay-ledger-v2", 50, Duration.ofSeconds(1));
    }

    private Path secret(String name, String value) throws Exception {
        Path path = directory.resolve(name);
        Files.writeString(path, value);
        Files.setPosixFilePermissions(path, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ));
        return path;
    }

    private static OutboxRelay.Message message(String payload) {
        return new OutboxRelay.Message(1,
                UUID.fromString("00000000-0000-0000-0000-000000000101"),
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                UUID.fromString("00000000-0000-0000-0000-000000000011"),
                "payment_intent",
                UUID.fromString("00000000-0000-0000-0000-000000000201"),
                1, "payment.captured.v1", 1, payload,
                Instant.parse("2026-08-30T01:00:00Z"),
                Instant.parse("2026-08-30T01:00:01Z"), "correlation-1",
                1, "worker-a", 1);
    }
}
