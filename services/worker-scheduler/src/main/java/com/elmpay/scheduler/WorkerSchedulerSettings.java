package com.elmpay.scheduler;

import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Fail-closed process configuration for the production scheduler deployment. */
public record WorkerSchedulerSettings(
        String workerId,
        String databaseUrl,
        String databaseUsername,
        Path databasePasswordFile,
        Path databaseCaFile,
        Path databaseClientCertificateFile,
        Path databaseClientPrivateKeyFile,
        Path adminActionPolicyBindingFile,
        Duration pollInterval,
        Duration readinessMaximumStaleness,
        int maximumScopesPerCycle,
        int maximumAdminCommandsPerCycle,
        Duration adminCommandLease,
        int maximumOutboxMessagesPerTenant,
        int maximumTimelineBatchesPerProject,
        int maximumBillingItemsPerTenant,
        List<String> reconciliationProviders,
        Duration reconciliationNotBeforeDelay,
        int maximumReconciliationJobsPerTenant,
        int reconciliationMaximumFacts,
        Duration reconciliationJobLease,
        int partitionMonthsAhead,
        String partitionActorId,
        String partitionTicketId,
        String healthHost,
        int healthPort,
        String kafkaBootstrapServers,
        String kafkaTopic,
        String kafkaClientId,
        Path kafkaTruststoreFile,
        Path kafkaTruststorePasswordFile,
        Path kafkaKeystoreFile,
        Path kafkaKeystorePasswordFile,
        Duration kafkaAcknowledgementTimeout,
        String kafkaConsumerGroupId,
        int kafkaConsumerMaxPollRecords,
        Duration kafkaConsumerPollTimeout) {

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{1,127}");
    private static final Pattern TOPIC = Pattern.compile("[a-zA-Z0-9][a-zA-Z0-9._-]{0,248}");

    public WorkerSchedulerSettings {
        workerId = identifier(workerId, "ELMPAY_WORKER_ID");
        databaseUrl = jdbcUrl(databaseUrl);
        databaseUsername = identifier(databaseUsername, "ELMPAY_DATABASE_USERNAME");
        if (!"elmpay_worker".equals(databaseUsername)) {
            throw new IllegalArgumentException(
                    "ELMPAY_DATABASE_USERNAME must be the dedicated elmpay_worker role");
        }
        databasePasswordFile = absolute(databasePasswordFile, "ELMPAY_DATABASE_PASSWORD_FILE");
        databaseCaFile = absolute(databaseCaFile, "ELMPAY_DATABASE_CA_FILE");
        databaseClientCertificateFile = absolute(databaseClientCertificateFile,
                "ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE");
        databaseClientPrivateKeyFile = absolute(databaseClientPrivateKeyFile,
                "ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE");
        adminActionPolicyBindingFile = absolute(adminActionPolicyBindingFile,
                "ELMPAY_ADMIN_ACTION_POLICY_BINDING_FILE");
        positiveBetween(pollInterval, Duration.ofMillis(100), Duration.ofMinutes(1),
                "ELMPAY_WORKER_POLL_INTERVAL");
        positiveBetween(readinessMaximumStaleness, pollInterval.multipliedBy(3),
                Duration.ofMinutes(10), "ELMPAY_WORKER_READINESS_MAX_STALENESS");
        bounded(maximumScopesPerCycle, 1, 10_000, "ELMPAY_WORKER_MAX_SCOPES");
        bounded(maximumAdminCommandsPerCycle, 1, 100,
                "ELMPAY_ADMIN_COMMAND_MAX_PER_CYCLE");
        positiveBetween(adminCommandLease, Duration.ofSeconds(5), Duration.ofSeconds(60),
                "ELMPAY_ADMIN_COMMAND_LEASE_TTL");
        bounded(maximumOutboxMessagesPerTenant, 1, 1_000,
                "ELMPAY_WORKER_MAX_OUTBOX_PER_TENANT");
        bounded(maximumTimelineBatchesPerProject, 1, 10_000,
                "ELMPAY_WORKER_MAX_TIMELINE_BATCHES");
        bounded(maximumBillingItemsPerTenant, 1, 10_000,
                "ELMPAY_WORKER_MAX_BILLING_ITEMS");
        reconciliationProviders = providers(reconciliationProviders);
        positiveBetween(reconciliationNotBeforeDelay, Duration.ofMinutes(5),
                Duration.ofDays(7), "ELMPAY_RECONCILIATION_NOT_BEFORE_DELAY");
        bounded(maximumReconciliationJobsPerTenant, 1, reconciliationProviders.size(),
                "ELMPAY_RECONCILIATION_MAX_JOBS_PER_TENANT");
        bounded(reconciliationMaximumFacts, 1, 1_000_000,
                "ELMPAY_RECONCILIATION_MAX_FACTS");
        positiveBetween(reconciliationJobLease, Duration.ofSeconds(30), Duration.ofHours(1),
                "ELMPAY_RECONCILIATION_JOB_LEASE_TTL");
        bounded(partitionMonthsAhead, 1, 23, "ELMPAY_WORKER_PARTITION_MONTHS_AHEAD");
        partitionActorId = identifier(partitionActorId, "ELMPAY_WORKER_PARTITION_ACTOR_ID");
        partitionTicketId = identifier(partitionTicketId, "ELMPAY_WORKER_PARTITION_TICKET_ID");
        healthHost = host(healthHost);
        bounded(healthPort, 1, 65_535, "ELMPAY_WORKER_HEALTH_PORT");
        kafkaBootstrapServers = bootstrapServers(kafkaBootstrapServers);
        kafkaTopic = topic(kafkaTopic);
        kafkaClientId = identifier(kafkaClientId, "ELMPAY_KAFKA_CLIENT_ID");
        kafkaTruststoreFile = absolute(kafkaTruststoreFile, "ELMPAY_KAFKA_TRUSTSTORE_FILE");
        kafkaTruststorePasswordFile = absolute(kafkaTruststorePasswordFile,
                "ELMPAY_KAFKA_TRUSTSTORE_PASSWORD_FILE");
        kafkaKeystoreFile = absolute(kafkaKeystoreFile, "ELMPAY_KAFKA_KEYSTORE_FILE");
        kafkaKeystorePasswordFile = absolute(kafkaKeystorePasswordFile,
                "ELMPAY_KAFKA_KEYSTORE_PASSWORD_FILE");
        positiveBetween(kafkaAcknowledgementTimeout, Duration.ofSeconds(1),
                Duration.ofSeconds(30), "ELMPAY_KAFKA_ACK_TIMEOUT");
        kafkaConsumerGroupId = identifier(kafkaConsumerGroupId,
                "ELMPAY_KAFKA_LEDGER_CONSUMER_GROUP_ID");
        bounded(kafkaConsumerMaxPollRecords, 1, 500,
                "ELMPAY_KAFKA_CONSUMER_MAX_POLL_RECORDS");
        positiveBetween(kafkaConsumerPollTimeout, Duration.ofMillis(100),
                Duration.ofSeconds(10), "ELMPAY_KAFKA_CONSUMER_POLL_TIMEOUT");
    }

    public static WorkerSchedulerSettings from(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        return new WorkerSchedulerSettings(
                required(environment, "ELMPAY_WORKER_ID"),
                required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USERNAME"),
                path(environment, "ELMPAY_DATABASE_PASSWORD_FILE"),
                path(environment, "ELMPAY_DATABASE_CA_FILE"),
                path(environment, "ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE"),
                path(environment, "ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                path(environment, "ELMPAY_ADMIN_ACTION_POLICY_BINDING_FILE"),
                duration(environment, "ELMPAY_WORKER_POLL_INTERVAL"),
                duration(environment, "ELMPAY_WORKER_READINESS_MAX_STALENESS"),
                integer(environment, "ELMPAY_WORKER_MAX_SCOPES"),
                integer(environment, "ELMPAY_ADMIN_COMMAND_MAX_PER_CYCLE"),
                duration(environment, "ELMPAY_ADMIN_COMMAND_LEASE_TTL"),
                integer(environment, "ELMPAY_WORKER_MAX_OUTBOX_PER_TENANT"),
                integer(environment, "ELMPAY_WORKER_MAX_TIMELINE_BATCHES"),
                integer(environment, "ELMPAY_WORKER_MAX_BILLING_ITEMS"),
                providers(required(environment, "ELMPAY_RECONCILIATION_PROVIDERS")),
                duration(environment, "ELMPAY_RECONCILIATION_NOT_BEFORE_DELAY"),
                integer(environment, "ELMPAY_RECONCILIATION_MAX_JOBS_PER_TENANT"),
                integer(environment, "ELMPAY_RECONCILIATION_MAX_FACTS"),
                duration(environment, "ELMPAY_RECONCILIATION_JOB_LEASE_TTL"),
                integer(environment, "ELMPAY_WORKER_PARTITION_MONTHS_AHEAD"),
                required(environment, "ELMPAY_WORKER_PARTITION_ACTOR_ID"),
                required(environment, "ELMPAY_WORKER_PARTITION_TICKET_ID"),
                required(environment, "ELMPAY_WORKER_HEALTH_HOST"),
                integer(environment, "ELMPAY_WORKER_HEALTH_PORT"),
                required(environment, "ELMPAY_KAFKA_BOOTSTRAP_SERVERS"),
                required(environment, "ELMPAY_KAFKA_TOPIC"),
                required(environment, "ELMPAY_KAFKA_CLIENT_ID"),
                path(environment, "ELMPAY_KAFKA_TRUSTSTORE_FILE"),
                path(environment, "ELMPAY_KAFKA_TRUSTSTORE_PASSWORD_FILE"),
                path(environment, "ELMPAY_KAFKA_KEYSTORE_FILE"),
                path(environment, "ELMPAY_KAFKA_KEYSTORE_PASSWORD_FILE"),
                duration(environment, "ELMPAY_KAFKA_ACK_TIMEOUT"),
                required(environment, "ELMPAY_KAFKA_LEDGER_CONSUMER_GROUP_ID"),
                integer(environment, "ELMPAY_KAFKA_CONSUMER_MAX_POLL_RECORDS"),
                duration(environment, "ELMPAY_KAFKA_CONSUMER_POLL_TIMEOUT"));
    }

    private static String required(Map<String, String> values, String key) {
        String value = values.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value.trim();
    }

    private static int integer(Map<String, String> values, String key) {
        try {
            return Integer.parseInt(required(values, key));
        } catch (NumberFormatException failure) {
            throw new IllegalStateException(key + " must be an integer", failure);
        }
    }

    private static Duration duration(Map<String, String> values, String key) {
        try {
            return Duration.parse(required(values, key));
        } catch (DateTimeParseException failure) {
            throw new IllegalStateException(key + " must be an ISO-8601 duration", failure);
        }
    }

    private static Path path(Map<String, String> values, String key) {
        return Path.of(required(values, key));
    }

    private static String identifier(String value, String field) {
        Objects.requireNonNull(value, field);
        if (!ID.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
        return value;
    }

    private static String jdbcUrl(String value) {
        return FileBackedPostgresDataSource.requirePostgresUrl(value);
    }

    private static List<String> providers(String value) {
        return providers(java.util.Arrays.asList(value.toLowerCase(java.util.Locale.ROOT)
                .split(",", -1)));
    }

    private static List<String> providers(List<String> values) {
        Objects.requireNonNull(values, "ELMPAY_RECONCILIATION_PROVIDERS");
        Set<String> allowed = Set.of("wechat", "alipay", "stripe", "paypal", "apple_pay");
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        for (String value : values) {
            if (value == null || !value.equals(value.trim()) || !allowed.contains(value)
                    || !unique.add(value)) {
                throw new IllegalArgumentException(
                        "ELMPAY_RECONCILIATION_PROVIDERS must be a unique governed list");
            }
        }
        if (unique.isEmpty()) {
            throw new IllegalArgumentException("ELMPAY_RECONCILIATION_PROVIDERS is empty");
        }
        return List.copyOf(unique);
    }

    private static Path absolute(Path value, String field) {
        Objects.requireNonNull(value, field);
        Path normalized = value.normalize();
        if (!normalized.isAbsolute()) {
            throw new IllegalArgumentException(field + " must be an absolute mounted path");
        }
        return normalized;
    }

    private static String host(String value) {
        Objects.requireNonNull(value, "ELMPAY_WORKER_HEALTH_HOST");
        if (!java.util.Set.of("0.0.0.0", "127.0.0.1", "::", "::1").contains(value)) {
            throw new IllegalArgumentException(
                    "ELMPAY_WORKER_HEALTH_HOST must be an explicit local or wildcard address");
        }
        return value;
    }

    private static String bootstrapServers(String value) {
        Objects.requireNonNull(value, "ELMPAY_KAFKA_BOOTSTRAP_SERVERS");
        String[] servers = value.split(",", -1);
        if (servers.length < 2 || servers.length > 16) {
            throw new IllegalArgumentException(
                    "ELMPAY_KAFKA_BOOTSTRAP_SERVERS requires 2..16 TLS brokers");
        }
        for (String server : servers) {
            if (!server.matches("[A-Za-z0-9.-]{1,253}:[1-9][0-9]{0,4}")) {
                throw new IllegalArgumentException("Kafka broker has an invalid host:port");
            }
            int port = Integer.parseInt(server.substring(server.lastIndexOf(':') + 1));
            if (port > 65_535) {
                throw new IllegalArgumentException("Kafka broker port is outside the valid range");
            }
        }
        return value;
    }

    private static String topic(String value) {
        Objects.requireNonNull(value, "ELMPAY_KAFKA_TOPIC");
        if (!TOPIC.matcher(value).matches() || value.equals(".") || value.equals("..")) {
            throw new IllegalArgumentException("ELMPAY_KAFKA_TOPIC has an invalid format");
        }
        return value;
    }

    private static void bounded(int value, int minimum, int maximum, String field) {
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(field + " must be " + minimum + ".." + maximum);
        }
    }

    private static void positiveBetween(Duration value, Duration minimum, Duration maximum,
            String field) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(field + " must be between " + minimum + " and "
                    + maximum);
        }
    }
}
