package com.elmpay.scheduler.data;

import com.elmpay.scheduler.FileBackedPostgresDataSource;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;

/** One-shot independent Ed25519 verifier; it never creates or detaches a partition. */
public final class ArchiveReceiptVerifierApplication {
    private static final String ROLE = ArchiveReceiptVerifierSchemaVerifier.ROLE;

    private ArchiveReceiptVerifierApplication() { }

    public static void main(String[] arguments) {
        if (arguments.length != 0) {
            throw new IllegalArgumentException("archive receipt verifier accepts no arguments");
        }
        Map<String, String> environment = System.getenv();
        if (!"verify-and-ingest".equals(required(environment,
                "ELMPAY_ARCHIVE_RECEIPT_MODE"))) {
            throw new IllegalStateException("archive receipt mode must be verify-and-ingest");
        }
        String username = required(environment, "ELMPAY_ARCHIVE_DATABASE_USERNAME");
        if (!ROLE.equals(username)) {
            throw new IllegalStateException("archive verifier database role is fixed");
        }
        FileBackedPostgresDataSource dataSource = new FileBackedPostgresDataSource(
                required(environment, "ELMPAY_ARCHIVE_DATABASE_URL"), username,
                path(environment, "ELMPAY_ARCHIVE_DATABASE_PASSWORD_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DATABASE_CA_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DATABASE_CLIENT_CERTIFICATE_FILE"),
                path(environment, "ELMPAY_ARCHIVE_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                "elmpay-archive-receipt-verifier");
        new ArchiveReceiptVerifierSchemaVerifier(dataSource).verify();
        ArchiveReceiptVerifier verifier = ArchiveReceiptVerifier.load(
                path(environment, "ELMPAY_ARCHIVE_TRUST_FILE"), Clock.systemUTC());
        ArchiveReceiptVerifier.VerifiedBundle bundle = verifier.verify(
                path(environment, "ELMPAY_ARCHIVE_RECEIPT_BUNDLE_FILE"));
        new JdbcArchiveReceiptStore(dataSource).ingest(bundle);
    }

    private static Path path(Map<String, String> environment, String key) {
        Path path = Path.of(required(environment, key)).normalize();
        if (!path.isAbsolute() || path.getFileName() == null) {
            throw new IllegalStateException(key + " must be an absolute mounted file");
        }
        return path;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank() || !value.equals(value.trim())
                || value.length() > 2_048 || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalStateException(key + " is required without control characters");
        }
        return value;
    }
}
