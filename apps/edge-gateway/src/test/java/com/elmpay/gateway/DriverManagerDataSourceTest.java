package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class DriverManagerDataSourceTest {
    @TempDir
    Path directory;

    @Test
    void readsRotatedPasswordPerConnectionAndPinsMutualTls() throws Exception {
        Path password = mounted("password", "first-secret\n");
        Path ca = mounted("ca.crt", "ca");
        Path certificate = mounted("tls.crt", "certificate");
        Path privateKey = mounted("tls.key", "private-key");
        AtomicReference<Properties> observed = new AtomicReference<>();
        DriverManagerDataSource source = new DriverManagerDataSource(
                "jdbc:postgresql://db.internal:5432/elmpay", "edge_role", password,
                ca, certificate, privateKey, "elmpay-edge-test", (url, properties) -> {
                    Properties copy = new Properties();
                    copy.putAll(properties);
                    observed.set(copy);
                    return null;
                });

        assertNull(source.getConnection());
        assertEquals("first-secret", observed.get().getProperty("password"));
        assertEquals("verify-full", observed.get().getProperty("sslmode"));
        assertEquals(ca.toString(), observed.get().getProperty("sslrootcert"));
        assertEquals(certificate.toString(), observed.get().getProperty("sslcert"));
        assertEquals(privateKey.toString(), observed.get().getProperty("sslkey"));
        assertEquals("elmpay-edge-test", observed.get().getProperty("ApplicationName"));

        writable(password);
        Files.writeString(password, "rotated-secret\n");
        readOnly(password);
        assertNull(source.getConnection());
        assertEquals("rotated-secret", observed.get().getProperty("password"));
    }

    @Test
    void rejectsCredentialOrTlsOverridesAndLegacyInlinePassword() {
        Map<String, String> base = Map.of(
                "ELMPAY_DATABASE_URL", "jdbc:postgresql://db.internal:5432/elmpay",
                "ELMPAY_DATABASE_USERNAME", "edge_role",
                "ELMPAY_DATABASE_PASSWORD_FILE", "/var/run/secrets/elmpay/db/password",
                "ELMPAY_DATABASE_CA_FILE", "/var/run/secrets/elmpay/db/ca.crt",
                "ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE", "/var/run/secrets/elmpay/db/tls.crt",
                "ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE", "/var/run/secrets/elmpay/db/tls.key");
        DriverManagerDataSource.fromEnvironment(base, "elmpay-edge");

        var queryOverride = new java.util.HashMap<>(base);
        queryOverride.put("ELMPAY_DATABASE_URL",
                "jdbc:postgresql://db.internal:5432/elmpay?sslmode=disable");
        assertThrows(IllegalArgumentException.class,
                () -> DriverManagerDataSource.fromEnvironment(queryOverride, "elmpay-edge"));

        var credentialOverride = new java.util.HashMap<>(base);
        credentialOverride.put("ELMPAY_DATABASE_URL",
                "jdbc:postgresql://user:password@db.internal:5432/elmpay");
        assertThrows(IllegalArgumentException.class,
                () -> DriverManagerDataSource.fromEnvironment(credentialOverride, "elmpay-edge"));

        var legacy = new java.util.HashMap<>(base);
        legacy.remove("ELMPAY_DATABASE_PASSWORD_FILE");
        legacy.put("ELMPAY_DATABASE_PASSWORD", "must-not-be-consumed");
        assertThrows(IllegalStateException.class,
                () -> DriverManagerDataSource.fromEnvironment(legacy, "elmpay-edge"));
    }

    @Test
    void rejectsWritableOrMalformedSecretMountsAndCallerOverrides() throws Exception {
        Path password = directory.resolve("password");
        Files.writeString(password, "secret");
        Path ca = mounted("ca.crt", "ca");
        Path certificate = mounted("tls.crt", "certificate");
        Path privateKey = mounted("tls.key", "private-key");
        DriverManagerDataSource source = new DriverManagerDataSource(
                "jdbc:postgresql://db.internal:5432/elmpay", "edge_role", password,
                ca, certificate, privateKey, "elmpay-edge-test", (url, properties) -> null);
        assertThrows(java.sql.SQLException.class, source::getConnection);
        assertThrows(SQLFeatureNotSupportedException.class,
                () -> source.getConnection("attacker", "attacker"));

        readOnly(password);
        assertNull(source.getConnection());
        writable(password);
        Files.writeString(password, "line-one\nline-two");
        readOnly(password);
        assertThrows(java.sql.SQLException.class, source::getConnection);
    }

    @Test
    void acceptsProjectedRotationSymlinkAndRejectsTargetOutsideMount() throws Exception {
        Path mount = Files.createDirectory(directory.resolve("mount"));
        Path revision = Files.createDirectory(mount.resolve("..2026_08_30"));
        Path target = revision.resolve("password");
        Files.writeString(target, "rotated-secret\n");
        readOnly(target);
        Files.createSymbolicLink(mount.resolve("..data"), revision.getFileName());
        Path projected = Files.createSymbolicLink(
                mount.resolve("password"), Path.of("..data", "password"));
        assertEquals("rotated-secret", DriverManagerDataSource.mountedSecret(projected));

        Path outside = directory.resolve("outside-password");
        Files.writeString(outside, "escaped-secret");
        readOnly(outside);
        Path escaped = Files.createSymbolicLink(mount.resolve("escaped"), outside);
        assertThrows(java.sql.SQLException.class,
                () -> DriverManagerDataSource.mountedSecret(escaped));
    }

    @Test
    void rejectsMalformedUtf8PasswordMount() throws Exception {
        Path malformed = directory.resolve("malformed-password");
        Files.write(malformed, new byte[] {(byte) 0xc3, (byte) 0x28});
        readOnly(malformed);
        assertThrows(java.sql.SQLException.class,
                () -> DriverManagerDataSource.mountedSecret(malformed));
    }

    private Path mounted(String name, String value) throws Exception {
        Path path = directory.resolve(name);
        Files.writeString(path, value);
        readOnly(path);
        return path;
    }

    private static void readOnly(Path path) throws Exception {
        Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ));
    }

    private static void writable(Path path) throws Exception {
        Files.setPosixFilePermissions(path, Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }
}
