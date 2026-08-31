package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class TenantEvidenceRuntimeFactoryTest {
    @TempDir
    private Path temporary;

    @Test
    void writableTrustDocumentFailsClosedBeforeDatabaseAccess() throws Exception {
        Path trust = temporary.resolve("tenant-evidence-trust.json");
        Files.writeString(trust, document());
        Files.setPosixFilePermissions(trust, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));

        assertThrows(IllegalStateException.class, () -> TenantEvidenceRuntimeFactory.create(
                environment(trust), dataSource(), clock()));
    }

    @Test
    void exactReadOnlyEd25519TrustDocumentBuildsProductionVerifier() throws Exception {
        Path mount = temporary.resolve("tenant-evidence-trust-mount");
        Files.createDirectory(mount);
        Path trust = mount.resolve("tenant-evidence-trust.json");
        Files.writeString(trust, document());
        Files.setPosixFilePermissions(trust, Set.of(PosixFilePermission.OWNER_READ));
        Files.setPosixFilePermissions(mount, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_EXECUTE));
        try {
            assertNotNull(TenantEvidenceRuntimeFactory.create(environment(trust), dataSource(),
                    clock()));
        } finally {
            Files.setPosixFilePermissions(mount, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
            Files.setPosixFilePermissions(trust, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        }
    }

    private static Map<String, String> environment(Path trust) {
        return Map.of("ELMPAY_TENANT_EVIDENCE_TRUST_FILE", trust.toString());
    }

    private static DriverManagerDataSource dataSource() {
        return new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/not-used",
                "not-used", Path.of("/tmp/elmpay-test-password"),
                Path.of("/tmp/elmpay-test-ca.pem"), Path.of("/tmp/elmpay-test-client.pem"),
                Path.of("/tmp/elmpay-test-client-key.pem"), "elmpay-test");
    }

    private static Clock clock() {
        return Clock.fixed(Instant.parse("2026-08-30T00:00:00Z"), ZoneOffset.UTC);
    }

    private static String document() throws GeneralSecurityException {
        byte[] publicKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
                .getPublic().getEncoded();
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(publicKey)
                + "\n-----END PUBLIC KEY-----";
        return Json.stringify(Map.of(
                "schemaVersion", 1L,
                "keys", List.of(Map.of(
                        "keyId", "tenant-authority-key-1",
                        "algorithm", "Ed25519",
                        "publicKeyPem", pem,
                        "signerIdentity", "tenant-authority-workload",
                        "authority", "licensed-tenant-authority",
                        "evidenceTypes", List.of("KYB_VERIFIED", "CONTRACT_SIGNED",
                                "SETTLEMENT_COMPLETE", "RETENTION_PERIOD_STARTED",
                                "KEK_DESTROYED"),
                        "notBefore", Instant.parse("2026-01-01T00:00:00Z").toString(),
                        "notAfter", Instant.parse("2027-01-01T00:00:00Z").toString(),
                        "revoked", false))));
    }
}
