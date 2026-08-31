package com.elmpay.webhook.ingress;

import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Fail-closed environment contract for the independent provider webhook processor. */
public record WebhookProcessorSettings(
        String processorId,
        String databaseUrl,
        String databaseUsername,
        Path databasePasswordFile,
        Path databaseCaFile,
        Path databaseClientCertificateFile,
        Path databaseClientPrivateKeyFile,
        Duration pollInterval,
        Duration readinessMaximumStaleness,
        int maximumTenantsPerCycle,
        Duration leaseTtl,
        Duration baseBackoff,
        Duration maximumBackoff,
        int maximumAttempts,
        String healthHost,
        int healthPort) {

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{1,127}");

    public WebhookProcessorSettings {
        processorId = identifier(processorId, "ELMPAY_WEBHOOK_PROCESSOR_ID");
        databaseUrl = jdbcUrl(databaseUrl);
        databaseUsername = identifier(databaseUsername, "ELMPAY_DATABASE_USERNAME");
        databasePasswordFile = absolute(databasePasswordFile,
                "ELMPAY_DATABASE_PASSWORD_FILE");
        databaseCaFile = absolute(databaseCaFile, "ELMPAY_DATABASE_CA_FILE");
        databaseClientCertificateFile = absolute(databaseClientCertificateFile,
                "ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE");
        databaseClientPrivateKeyFile = absolute(databaseClientPrivateKeyFile,
                "ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE");
        duration(pollInterval, Duration.ofMillis(100), Duration.ofSeconds(30),
                "ELMPAY_WEBHOOK_PROCESSOR_POLL_INTERVAL");
        duration(readinessMaximumStaleness, pollInterval.multipliedBy(3),
                Duration.ofMinutes(10), "ELMPAY_WEBHOOK_PROCESSOR_READINESS_MAX_STALENESS");
        bounded(maximumTenantsPerCycle, 1, 1000,
                "ELMPAY_WEBHOOK_PROCESSOR_MAX_TENANTS");
        duration(leaseTtl, Duration.ofSeconds(5), Duration.ofMinutes(5),
                "ELMPAY_WEBHOOK_PROCESSOR_LEASE_TTL");
        duration(baseBackoff, Duration.ofMillis(100), Duration.ofMinutes(5),
                "ELMPAY_WEBHOOK_PROCESSOR_BASE_BACKOFF");
        duration(maximumBackoff, baseBackoff, Duration.ofHours(1),
                "ELMPAY_WEBHOOK_PROCESSOR_MAX_BACKOFF");
        bounded(maximumAttempts, 1, 100, "ELMPAY_WEBHOOK_PROCESSOR_MAX_ATTEMPTS");
        healthHost = healthHost(healthHost);
        bounded(healthPort, 1, 65_535, "ELMPAY_WEBHOOK_PROCESSOR_HEALTH_PORT");
    }

    public static WebhookProcessorSettings from(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        return new WebhookProcessorSettings(
                required(environment, "ELMPAY_WEBHOOK_PROCESSOR_ID"),
                required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USERNAME"),
                path(environment, "ELMPAY_DATABASE_PASSWORD_FILE"),
                path(environment, "ELMPAY_DATABASE_CA_FILE"),
                path(environment, "ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE"),
                path(environment, "ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                duration(environment, "ELMPAY_WEBHOOK_PROCESSOR_POLL_INTERVAL"),
                duration(environment, "ELMPAY_WEBHOOK_PROCESSOR_READINESS_MAX_STALENESS"),
                integer(environment, "ELMPAY_WEBHOOK_PROCESSOR_MAX_TENANTS"),
                duration(environment, "ELMPAY_WEBHOOK_PROCESSOR_LEASE_TTL"),
                duration(environment, "ELMPAY_WEBHOOK_PROCESSOR_BASE_BACKOFF"),
                duration(environment, "ELMPAY_WEBHOOK_PROCESSOR_MAX_BACKOFF"),
                integer(environment, "ELMPAY_WEBHOOK_PROCESSOR_MAX_ATTEMPTS"),
                required(environment, "ELMPAY_WEBHOOK_PROCESSOR_HEALTH_HOST"),
                integer(environment, "ELMPAY_WEBHOOK_PROCESSOR_HEALTH_PORT"));
    }

    public WebhookInboxProcessor.Policy processingPolicy() {
        return new WebhookInboxProcessor.Policy(leaseTtl, baseBackoff, maximumBackoff,
                maximumAttempts);
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
        Objects.requireNonNull(value, "ELMPAY_DATABASE_URL");
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        if (!lower.startsWith("jdbc:postgresql://") || value.contains("?")
                || value.contains("#") || lower.contains("user=")
                || lower.contains("password=") || lower.contains("sslmode=")
                || lower.contains("sslrootcert=") || lower.contains("sslcert=")
                || lower.contains("sslkey=") || value.length() > 2_048) {
            throw new IllegalArgumentException(
                    "ELMPAY_DATABASE_URL must not override credentials or TLS policy");
        }
        return value;
    }

    private static Path absolute(Path value, String field) {
        Objects.requireNonNull(value, field);
        Path normalized = value.normalize();
        if (!normalized.isAbsolute()) {
            throw new IllegalArgumentException(field + " must be an absolute mounted path");
        }
        return normalized;
    }

    private static String healthHost(String value) {
        Objects.requireNonNull(value, "ELMPAY_WEBHOOK_PROCESSOR_HEALTH_HOST");
        if (!Set.of("0.0.0.0", "127.0.0.1", "::", "::1").contains(value)) {
            throw new IllegalArgumentException(
                    "ELMPAY_WEBHOOK_PROCESSOR_HEALTH_HOST is not an explicit bind address");
        }
        return value;
    }

    private static void bounded(int value, int minimum, int maximum, String field) {
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(field + " must be " + minimum + ".." + maximum);
        }
    }

    private static void duration(Duration value, Duration minimum, Duration maximum,
            String field) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(field + " must be between " + minimum + " and "
                    + maximum);
        }
    }
}
