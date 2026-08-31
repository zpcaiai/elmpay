package com.elmpay.scheduler.data;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

/** Exact mounted configuration for the one-shot/Cron partition precreator. */
public record PartitionMaintenanceSettings(String databaseUrl, String databaseUsername,
        Path databasePasswordFile, Path databaseCaFile, Path databaseClientCertificateFile,
        Path databaseClientPrivateKeyFile, int monthsAhead, String actorId, String ticketId) {
    public static final String DATABASE_ROLE = "elmpay_partition_precreator";

    public PartitionMaintenanceSettings {
        databaseUrl = required(databaseUrl, "ELMPAY_PARTITION_DATABASE_URL");
        databaseUsername = required(databaseUsername, "ELMPAY_PARTITION_DATABASE_USERNAME");
        if (!DATABASE_ROLE.equals(databaseUsername)) {
            throw new IllegalArgumentException("partition maintenance database role is fixed");
        }
        databasePasswordFile = absolute(databasePasswordFile,
                "ELMPAY_PARTITION_DATABASE_PASSWORD_FILE");
        databaseCaFile = absolute(databaseCaFile, "ELMPAY_PARTITION_DATABASE_CA_FILE");
        databaseClientCertificateFile = absolute(databaseClientCertificateFile,
                "ELMPAY_PARTITION_DATABASE_CLIENT_CERTIFICATE_FILE");
        databaseClientPrivateKeyFile = absolute(databaseClientPrivateKeyFile,
                "ELMPAY_PARTITION_DATABASE_CLIENT_PRIVATE_KEY_FILE");
        if (monthsAhead < 1 || monthsAhead > 23) {
            throw new IllegalArgumentException("partition horizon must be 1..23 months");
        }
        actorId = identifier(actorId, "ELMPAY_PARTITION_ACTOR_ID");
        ticketId = identifier(ticketId, "ELMPAY_PARTITION_TICKET_ID");
    }

    public static PartitionMaintenanceSettings from(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        return new PartitionMaintenanceSettings(
                required(environment.get("ELMPAY_PARTITION_DATABASE_URL"),
                        "ELMPAY_PARTITION_DATABASE_URL"),
                required(environment.get("ELMPAY_PARTITION_DATABASE_USERNAME"),
                        "ELMPAY_PARTITION_DATABASE_USERNAME"),
                path(environment, "ELMPAY_PARTITION_DATABASE_PASSWORD_FILE"),
                path(environment, "ELMPAY_PARTITION_DATABASE_CA_FILE"),
                path(environment, "ELMPAY_PARTITION_DATABASE_CLIENT_CERTIFICATE_FILE"),
                path(environment, "ELMPAY_PARTITION_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                integer(environment, "ELMPAY_PARTITION_MONTHS_AHEAD"),
                required(environment.get("ELMPAY_PARTITION_ACTOR_ID"),
                        "ELMPAY_PARTITION_ACTOR_ID"),
                required(environment.get("ELMPAY_PARTITION_TICKET_ID"),
                        "ELMPAY_PARTITION_TICKET_ID"));
    }

    private static Path path(Map<String, String> environment, String key) {
        return Path.of(required(environment.get(key), key));
    }

    private static int integer(Map<String, String> environment, String key) {
        try {
            return Integer.parseInt(required(environment.get(key), key));
        } catch (NumberFormatException failure) {
            throw new IllegalStateException(key + " must be an integer", failure);
        }
    }

    private static Path absolute(Path value, String field) {
        Objects.requireNonNull(value, field);
        Path normalized = value.normalize();
        if (!normalized.isAbsolute() || normalized.getFileName() == null) {
            throw new IllegalArgumentException(field + " must be an absolute mounted file");
        }
        return normalized;
    }

    private static String identifier(String value, String field) {
        String normalized = required(value, field);
        if (!normalized.matches("[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return normalized;
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank() || !value.equals(value.trim())
                || value.length() > 2_048 || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalStateException(field + " is required without control characters");
        }
        return value;
    }
}
