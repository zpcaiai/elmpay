package com.elmpay.scheduler.data;

import com.elmpay.scheduler.FileBackedPostgresDataSource;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;

/** Verifies and stages a short-lived detach authorization; it cannot execute detach. */
public final class ArchiveDetachAuthorizationVerifierApplication {
    private ArchiveDetachAuthorizationVerifierApplication() { }

    public static void main(String[] arguments) {
        if (arguments.length != 0) {
            throw new IllegalArgumentException(
                    "archive detach authorization verifier accepts no arguments");
        }
        Map<String, String> environment = System.getenv();
        if (!"verify-detach-authorization".equals(required(
                environment, "ELMPAY_ARCHIVE_DETACH_VERIFIER_MODE"))) {
            throw new IllegalStateException("archive detach verifier mode is invalid");
        }
        String username = required(environment, "ELMPAY_ARCHIVE_DATABASE_USERNAME");
        if (!ArchiveReceiptVerifierSchemaVerifier.ROLE.equals(username)) {
            throw new IllegalStateException("archive verifier database role is fixed");
        }
        FileBackedPostgresDataSource dataSource = new FileBackedPostgresDataSource(
                required(environment, "ELMPAY_ARCHIVE_DATABASE_URL"), username,
                path(environment, "ELMPAY_ARCHIVE_DATABASE_PASSWORD_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DATABASE_CA_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DATABASE_CLIENT_CERTIFICATE_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                "elmpay-archive-detach-authorization-verifier");
        new ArchiveReceiptVerifierSchemaVerifier(dataSource).verify();
        ArchiveReceiptVerifier verifier = ArchiveReceiptVerifier.load(
                path(environment, "ELMPAY_ARCHIVE_TRUST_FILE"), Clock.systemUTC());
        ArchiveDetachPolicyBinding policy = ArchiveDetachPolicyBinding.load(
                path(environment, "ELMPAY_ARCHIVE_DETACH_POLICY_FILE"));
        ArchiveReceiptVerifier.VerifiedDetachAuthorization authorization =
                verifier.verifyDetachAuthorization(
                        path(environment, "ELMPAY_ARCHIVE_DETACH_AUTHORIZATION_FILE"), policy);
        new JdbcArchiveDetachAuthorizationStore(dataSource).ingest(authorization);
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
