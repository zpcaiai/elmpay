package com.elmpay.scheduler.data;

import java.nio.file.Path;
import java.util.Map;

/** Mounted-only configuration for the manually instantiated destructive detach job. */
record ArchivePartitionDetacherSettings(String databaseUrl, String databaseUsername,
        Path databasePasswordFile, Path databaseCaFile, Path databaseClientCertificateFile,
        Path databaseClientPrivateKeyFile, Path executionRequestFile) {
    static final String DATABASE_ROLE = "elmpay_partition_detacher";

    static ArchivePartitionDetacherSettings from(Map<String, String> environment) {
        return new ArchivePartitionDetacherSettings(
                required(environment, "ELMPAY_ARCHIVE_DETACH_DATABASE_URL"),
                required(environment, "ELMPAY_ARCHIVE_DETACH_DATABASE_USERNAME"),
                path(environment, "ELMPAY_ARCHIVE_DETACH_DATABASE_PASSWORD_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DETACH_DATABASE_CA_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DETACH_DATABASE_CLIENT_CERTIFICATE_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DETACH_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DETACH_EXECUTION_REQUEST_FILE"));
    }

    ArchivePartitionDetacherSettings {
        if (!DATABASE_ROLE.equals(databaseUsername)) {
            throw new IllegalArgumentException("archive detacher database role is fixed");
        }
    }

    private static Path path(Map<String, String> environment, String field) {
        Path value = Path.of(required(environment, field)).normalize();
        if (!value.isAbsolute() || value.getFileName() == null) {
            throw new IllegalStateException(field + " must be an absolute mounted file");
        }
        return value;
    }

    private static String required(Map<String, String> environment, String field) {
        String value = environment.get(field);
        if (value == null || value.isBlank() || !value.equals(value.trim())
                || value.length() > 2_048
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalStateException(field + " is required without control characters");
        }
        return value;
    }
}
