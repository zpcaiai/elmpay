package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileBackedPostgresDataSourceTest {
    @TempDir
    Path directory;

    @Test
    void readsOneMountedSecretWithoutDestroyingValidWhitespace() throws Exception {
        Path newline = directory.resolve("newline");
        Files.writeString(newline, "secret phrase\n");
        readOnly(newline);
        assertEquals("secret phrase", FileBackedPostgresDataSource.mountedSecret(newline));

        Path trailingSpace = directory.resolve("space");
        Files.writeString(trailingSpace, "secret ");
        readOnly(trailingSpace);
        assertEquals("secret ", FileBackedPostgresDataSource.mountedSecret(trailingSpace));
    }

    @Test
    void rejectsMissingEmptyOversizedAndMultilineSecrets() throws Exception {
        assertThrows(SQLException.class, () -> FileBackedPostgresDataSource.mountedSecret(
                directory.resolve("missing")));
        Path empty = directory.resolve("empty");
        Files.writeString(empty, "");
        readOnly(empty);
        assertThrows(SQLException.class,
                () -> FileBackedPostgresDataSource.mountedSecret(empty));
        Path multiline = directory.resolve("multiline");
        Files.writeString(multiline, "first\nsecond");
        readOnly(multiline);
        assertThrows(SQLException.class,
                () -> FileBackedPostgresDataSource.mountedSecret(multiline));
        Path huge = directory.resolve("huge");
        Files.writeString(huge, "x".repeat(8_193));
        readOnly(huge);
        assertThrows(SQLException.class,
                () -> FileBackedPostgresDataSource.mountedSecret(huge));
    }

    @Test
    void disallowsCallerCredentialAndDriverLoggingOverrides() throws Exception {
        Path password = directory.resolve("password");
        Files.writeString(password, "secret");
        readOnly(password);
        FileBackedPostgresDataSource source = source(password);
        source.setLoginTimeout(12);
        assertEquals(12, source.getLoginTimeout());
        assertThrows(IllegalArgumentException.class, () -> source.setLoginTimeout(0));
        assertThrows(SQLFeatureNotSupportedException.class,
                () -> source.getConnection("override", "override"));
        assertThrows(SQLFeatureNotSupportedException.class,
                () -> source.setLogWriter(new PrintWriter(System.out)));
        source.setLogWriter(null);
        assertNull(source.getLogWriter());
        assertThrows(SQLFeatureNotSupportedException.class, source::getParentLogger);
        assertTrue(source.isWrapperFor(FileBackedPostgresDataSource.class));
        assertFalse(source.isWrapperFor(String.class));
        assertSame(source, source.unwrap(FileBackedPostgresDataSource.class));
        assertThrows(SQLException.class, () -> source.unwrap(String.class));
    }

    @Test
    void connectionAlwaysAppliesVerifyFullAndMountedClientIdentity() throws Exception {
        Path password = directory.resolve("password");
        Files.writeString(password, "secret");
        readOnly(password);
        Path ca = directory.resolve("ca.crt");
        Path certificate = directory.resolve("client.crt");
        Path privateKey = directory.resolve("client.key");
        pem(ca, "CERTIFICATE");
        pem(certificate, "CERTIFICATE");
        pem(privateKey, "PRIVATE KEY");
        AtomicReference<Properties> captured = new AtomicReference<>();
        AtomicReference<Properties> transientProperties = new AtomicReference<>();
        FileBackedPostgresDataSource source = new FileBackedPostgresDataSource(
                "jdbc:postgresql://db.internal:5432/elmpay", "worker", password, ca, certificate,
                privateKey, (url, properties) -> {
                    transientProperties.set(properties);
                    Properties copy = new Properties();
                    copy.putAll(properties);
                    captured.set(copy);
                    return connection();
                });
        Connection opened = source.getConnection();
        try {
            assertEquals("verify-full", captured.get().getProperty("sslmode"));
            assertEquals(ca.toRealPath().toString(),
                    captured.get().getProperty("sslrootcert"));
            assertEquals(certificate.toRealPath().toString(),
                    captured.get().getProperty("sslcert"));
            assertEquals(privateKey.toRealPath().toString(),
                    captured.get().getProperty("sslkey"));
            assertEquals("secret", captured.get().getProperty("password"));
        } finally {
            opened.close();
        }
        assertTrue(transientProperties.get().isEmpty());
    }

    @Test
    void rejectsBinaryPrivateKeyMaterialBeforeOpeningAConnection() throws Exception {
        Path password = directory.resolve("password-binary-key-test");
        Files.writeString(password, "secret");
        readOnly(password);
        Path ca = directory.resolve("binary-key-ca.crt");
        Path certificate = directory.resolve("binary-key-client.crt");
        Path privateKey = directory.resolve("binary-client.key");
        pem(ca, "CERTIFICATE");
        pem(certificate, "CERTIFICATE");
        byte[] invalid = ("-----BEGIN PRIVATE KEY-----\n" + "A".repeat(80)
                + "\n-----END PRIVATE KEY-----\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        invalid[40] = 0;
        Files.write(privateKey, invalid);
        java.util.Arrays.fill(invalid, (byte) 0);
        readOnly(privateKey);
        FileBackedPostgresDataSource source = new FileBackedPostgresDataSource(
                "jdbc:postgresql://db.internal:5432/elmpay", "worker", password, ca, certificate,
                privateKey, (url, properties) -> connection());
        assertThrows(SQLException.class, source::getConnection);
    }

    @Test
    void constructorRequiresPostgresAndAnAbsoluteMount() {
        assertThrows(IllegalArgumentException.class, () -> new FileBackedPostgresDataSource(
                "jdbc:mysql://db/elmpay", "worker", directory.resolve("password"),
                directory.resolve("ca"), directory.resolve("cert"), directory.resolve("key")));
        assertThrows(IllegalArgumentException.class, () -> new FileBackedPostgresDataSource(
                "jdbc:postgresql://db:5432/elmpay", "", directory.resolve("password"),
                directory.resolve("ca"), directory.resolve("cert"), directory.resolve("key")));
        assertThrows(IllegalArgumentException.class, () -> new FileBackedPostgresDataSource(
                "jdbc:postgresql://db:5432/elmpay", "worker", Path.of("password"),
                directory.resolve("ca"), directory.resolve("cert"), directory.resolve("key")));
        for (String url : java.util.List.of(
                "jdbc:postgresql://user@db:5432/elmpay",
                "jdbc:postgresql://db/elmpay",
                "jdbc:postgresql://db:5432/elmpay?sslmode=disable",
                "jdbc:postgresql://db:5432/elmpay#password=x",
                "jdbc:postgresql://db:5432/elmpay/extra",
                "jdbc:postgresql://db:5432/elm%70ay")) {
            assertThrows(IllegalArgumentException.class,
                    () -> FileBackedPostgresDataSource.requirePostgresUrl(url));
        }
    }

    @Test
    void permitsOnlyInMountKubernetesDataRotationAndPinsEachConnection() throws Exception {
        Path mount = Files.createDirectory(directory.resolve("mount"));
        Path first = Files.createDirectory(mount.resolve("..2026_08_30_01"));
        Path second = Files.createDirectory(mount.resolve("..2026_08_30_02"));
        Path firstSecret = first.resolve("password");
        Path secondSecret = second.resolve("password");
        Files.writeString(firstSecret, "first-secret");
        Files.writeString(secondSecret, "second-secret");
        readOnly(firstSecret);
        readOnly(secondSecret);
        Path data = mount.resolve("..data");
        Files.createSymbolicLink(data, first.getFileName());
        Path projected = mount.resolve("password");
        Files.createSymbolicLink(projected, Path.of("..data/password"));
        assertEquals("first-secret", FileBackedPostgresDataSource.mountedSecret(projected));
        Files.delete(data);
        Files.createSymbolicLink(data, second.getFileName());
        assertEquals("second-secret", FileBackedPostgresDataSource.mountedSecret(projected));

        Path outside = directory.resolve("outside");
        Files.writeString(outside, "stolen");
        readOnly(outside);
        Path escaping = mount.resolve("escape");
        Files.createSymbolicLink(escaping, Path.of("../outside"));
        assertThrows(SQLException.class,
                () -> FileBackedPostgresDataSource.mountedSecret(escaping));
    }

    @Test
    void rejectsWritableMountedMaterial() throws Exception {
        Path writable = directory.resolve("writable");
        Files.writeString(writable, "secret");
        assertThrows(SQLException.class,
                () -> FileBackedPostgresDataSource.mountedSecret(writable));
    }

    private FileBackedPostgresDataSource source(Path password) throws Exception {
        Path ca = directory.resolve("ca.crt");
        Path certificate = directory.resolve("client.crt");
        Path privateKey = directory.resolve("client.key");
        pem(ca, "CERTIFICATE");
        pem(certificate, "CERTIFICATE");
        pem(privateKey, "PRIVATE KEY");
        return new FileBackedPostgresDataSource("jdbc:postgresql://db.internal:5432/elmpay", "worker",
                password, ca, certificate, privateKey);
    }

    private static void pem(Path path, String type) throws Exception {
        Files.writeString(path, "-----BEGIN " + type + "-----\n"
                + "A".repeat(96) + "\n-----END " + type + "-----\n");
        readOnly(path);
    }

    private static void readOnly(Path path) throws Exception {
        Files.setPosixFilePermissions(path, java.util.Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ));
    }

    private static Connection connection() {
        return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                Connection.class.getClassLoader(), new Class<?>[] {Connection.class},
                (target, method, arguments) -> method.getReturnType() == boolean.class
                        ? false : null);
    }
}
