package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class WorkerSchedulerSettingsTest {
    @Test
    void parsesEveryProductionBoundaryExplicitly() {
        WorkerSchedulerSettings settings = WorkerSchedulerSettings.from(environment());
        assertEquals("worker-a", settings.workerId());
        assertEquals(Duration.ofSeconds(2), settings.pollInterval());
        assertEquals(100, settings.maximumScopesPerCycle());
        assertEquals(5, settings.maximumAdminCommandsPerCycle());
        assertEquals(java.util.List.of("stripe", "paypal"),
                settings.reconciliationProviders());
        assertEquals("payment.events.v1", settings.kafkaTopic());
        assertEquals(9093, Integer.parseInt(settings.kafkaBootstrapServers().split(":")[1]
                .split(",")[0]));
    }

    @Test
    void missingMalformedAndUnsafeConfigurationFailsClosed() {
        Map<String, String> missing = environment();
        missing.remove("ELMPAY_DATABASE_PASSWORD_FILE");
        assertThrows(IllegalStateException.class, () -> WorkerSchedulerSettings.from(missing));

        Map<String, String> badDuration = environment();
        badDuration.put("ELMPAY_WORKER_POLL_INTERVAL", "two seconds");
        assertThrows(IllegalStateException.class,
                () -> WorkerSchedulerSettings.from(badDuration));

        Map<String, String> badInteger = environment();
        badInteger.put("ELMPAY_WORKER_MAX_SCOPES", "many");
        assertThrows(IllegalStateException.class,
                () -> WorkerSchedulerSettings.from(badInteger));

        Map<String, String> wrongDatabaseRole = environment();
        wrongDatabaseRole.put("ELMPAY_DATABASE_USERNAME", "shared_application_role");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(wrongDatabaseRole));

        Map<String, String> credentialsInUrl = environment();
        credentialsInUrl.put("ELMPAY_DATABASE_URL",
                "jdbc:postgresql://db/elmpay?user=admin&password=secret");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(credentialsInUrl));

        Map<String, String> tlsOverride = environment();
        tlsOverride.put("ELMPAY_DATABASE_URL",
                "jdbc:postgresql://db/elmpay?sslmode=disable");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(tlsOverride));

        Map<String, String> singleBroker = environment();
        singleBroker.put("ELMPAY_KAFKA_BOOTSTRAP_SERVERS", "broker-1:9093");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(singleBroker));

        Map<String, String> badTopic = environment();
        badTopic.put("ELMPAY_KAFKA_TOPIC", "../events");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(badTopic));

        Map<String, String> relativeMount = environment();
        relativeMount.put("ELMPAY_KAFKA_KEYSTORE_FILE", "secret.p12");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(relativeMount));

        Map<String, String> jdbcFragment = environment();
        jdbcFragment.put("ELMPAY_DATABASE_URL",
                "jdbc:postgresql://db.internal:5432/elmpay#sslmode=disable");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(jdbcFragment));

        Map<String, String> duplicateProviders = environment();
        duplicateProviders.put("ELMPAY_RECONCILIATION_PROVIDERS", "stripe,stripe");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(duplicateProviders));
    }

    @Test
    void configuredBoundsCannotDisableFairnessOrFreshness() {
        Map<String, String> tooFast = environment();
        tooFast.put("ELMPAY_WORKER_POLL_INTERVAL", "PT0.01S");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(tooFast));

        Map<String, String> staleTooSoon = environment();
        staleTooSoon.put("ELMPAY_WORKER_READINESS_MAX_STALENESS", "PT3S");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(staleTooSoon));

        Map<String, String> unbounded = environment();
        unbounded.put("ELMPAY_WORKER_MAX_BILLING_ITEMS", "10001");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(unbounded));

        Map<String, String> slowAck = environment();
        slowAck.put("ELMPAY_KAFKA_ACK_TIMEOUT", "PT31S");
        assertThrows(IllegalArgumentException.class,
                () -> WorkerSchedulerSettings.from(slowAck));
    }

    static WorkerSchedulerSettings settings() {
        return WorkerSchedulerSettings.from(environment());
    }

    private static Map<String, String> environment() {
        Map<String, String> values = new HashMap<>();
        values.put("ELMPAY_WORKER_ID", "worker-a");
        values.put("ELMPAY_DATABASE_URL", "jdbc:postgresql://db.internal:5432/elmpay");
        values.put("ELMPAY_DATABASE_USERNAME", "elmpay_worker");
        values.put("ELMPAY_DATABASE_PASSWORD_FILE", Path.of("/var/run/secrets/db/password").toString());
        values.put("ELMPAY_DATABASE_CA_FILE", "/var/run/secrets/db/ca.crt");
        values.put("ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE", "/var/run/secrets/db/tls.crt");
        values.put("ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE", "/var/run/secrets/db/tls.key");
        values.put("ELMPAY_ADMIN_ACTION_POLICY_BINDING_FILE",
                "/var/run/secrets/admin-governance/policy-binding.json");
        values.put("ELMPAY_WORKER_POLL_INTERVAL", "PT2S");
        values.put("ELMPAY_WORKER_READINESS_MAX_STALENESS", "PT30S");
        values.put("ELMPAY_WORKER_MAX_SCOPES", "100");
        values.put("ELMPAY_ADMIN_COMMAND_MAX_PER_CYCLE", "5");
        values.put("ELMPAY_ADMIN_COMMAND_LEASE_TTL", "PT30S");
        values.put("ELMPAY_WORKER_MAX_OUTBOX_PER_TENANT", "50");
        values.put("ELMPAY_WORKER_MAX_TIMELINE_BATCHES", "25");
        values.put("ELMPAY_WORKER_MAX_BILLING_ITEMS", "20");
        values.put("ELMPAY_RECONCILIATION_PROVIDERS", "stripe,paypal");
        values.put("ELMPAY_RECONCILIATION_NOT_BEFORE_DELAY", "PT2H");
        values.put("ELMPAY_RECONCILIATION_MAX_JOBS_PER_TENANT", "1");
        values.put("ELMPAY_RECONCILIATION_MAX_FACTS", "100000");
        values.put("ELMPAY_RECONCILIATION_JOB_LEASE_TTL", "PT10M");
        values.put("ELMPAY_WORKER_PARTITION_MONTHS_AHEAD", "6");
        values.put("ELMPAY_WORKER_PARTITION_ACTOR_ID", "worker-scheduler");
        values.put("ELMPAY_WORKER_PARTITION_TICKET_ID", "scheduled-partition-maintenance");
        values.put("ELMPAY_WORKER_HEALTH_HOST", "127.0.0.1");
        values.put("ELMPAY_WORKER_HEALTH_PORT", "8081");
        values.put("ELMPAY_KAFKA_BOOTSTRAP_SERVERS",
                "broker-1.internal:9093,broker-2.internal:9093");
        values.put("ELMPAY_KAFKA_TOPIC", "payment.events.v1");
        values.put("ELMPAY_KAFKA_CLIENT_ID", "elmpay-worker-a");
        values.put("ELMPAY_KAFKA_TRUSTSTORE_FILE", "/var/run/secrets/kafka/truststore.p12");
        values.put("ELMPAY_KAFKA_TRUSTSTORE_PASSWORD_FILE",
                "/var/run/secrets/kafka/truststore-password");
        values.put("ELMPAY_KAFKA_KEYSTORE_FILE", "/var/run/secrets/kafka/keystore.p12");
        values.put("ELMPAY_KAFKA_KEYSTORE_PASSWORD_FILE",
                "/var/run/secrets/kafka/keystore-password");
        values.put("ELMPAY_KAFKA_ACK_TIMEOUT", "PT5S");
        values.put("ELMPAY_KAFKA_LEDGER_CONSUMER_GROUP_ID", "elmpay-ledger-v2");
        values.put("ELMPAY_KAFKA_CONSUMER_MAX_POLL_RECORDS", "50");
        values.put("ELMPAY_KAFKA_CONSUMER_POLL_TIMEOUT", "PT1S");
        return values;
    }
}
