package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileBackedWebhookPostgresDataSourceTest {
    @TempDir Path temporary;

    @Test
    void loadsMountedPasswordAndForcesVerifyFullMutualTls() throws Exception {
        Path password = mounted("password", "rotated-secret\n");
        Path ca = mounted("ca.crt", "ca");
        Path certificate = mounted("tls.crt", "certificate");
        Path key = mounted("tls.key", "key");
        AtomicReference<Properties> captured = new AtomicReference<>();
        Connection connection = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, arguments) -> switch (method.getName()) {
                    case "equals" -> proxy == arguments[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "toString" -> "test-connection";
                    default -> null;
                });
        FileBackedWebhookPostgresDataSource source =
                new FileBackedWebhookPostgresDataSource(
                        "jdbc:postgresql://postgres:5432/elmpay",
                        "elmpay_webhook_processor", password, ca, certificate, key,
                        (url, properties) -> {
                            captured.set(properties);
                            return connection;
                        });

        assertEquals(connection, source.getConnection());
        assertEquals("rotated-secret", captured.get().getProperty("password"));
        assertEquals("verify-full", captured.get().getProperty("sslmode"));
        assertEquals(ca.toString(), captured.get().getProperty("sslrootcert"));
        assertEquals(certificate.toString(), captured.get().getProperty("sslcert"));
        assertEquals(key.toString(), captured.get().getProperty("sslkey"));
        assertEquals("elmpay-webhook-processor",
                captured.get().getProperty("ApplicationName"));
    }

    @Test
    void rejectsWritableSecretMountAndCredentialOverride() throws Exception {
        Path writable = temporary.resolve("writable");
        Files.writeString(writable, "secret", StandardCharsets.UTF_8);
        assertThrows(SQLException.class,
                () -> FileBackedWebhookPostgresDataSource.mountedSecret(writable));

        Path mounted = mounted("password", "secret");
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> new FileBackedWebhookPostgresDataSource(
                        "jdbc:postgresql://postgres/elmpay?password=inline", "worker", mounted,
                        mounted, mounted, mounted));
        assertTrue(failure.getMessage().contains("invalid PostgreSQL"));
        assertThrows(IllegalArgumentException.class,
                () -> new FileBackedWebhookPostgresDataSource(
                        "jdbc:postgresql://user:secret@postgres:5432/elmpay", "worker", mounted,
                        mounted, mounted, mounted));
        assertThrows(IllegalArgumentException.class,
                () -> new FileBackedWebhookPostgresDataSource(
                        "jdbc:postgresql://postgres:70000/elmpay", "worker", mounted,
                        mounted, mounted, mounted));
    }

    @Test
    void acceptsContainedKubernetesProjectedSecretButRejectsEscapingSymlink() throws Exception {
        Path volume = Files.createDirectory(temporary.resolve("projected"));
        Path revision = Files.createDirectory(volume.resolve("..2026_08_30"));
        Path target = revision.resolve("password");
        Files.writeString(target, "rotated-secret", StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--r-----"));
        Path projected = Files.createSymbolicLink(volume.resolve("password"),
                Path.of("..2026_08_30/password"));
        assertEquals("rotated-secret",
                FileBackedWebhookPostgresDataSource.mountedSecret(projected));

        Path outside = mounted("outside", "must-not-resolve");
        Path escaping = Files.createSymbolicLink(volume.resolve("escape"), outside);
        assertThrows(SQLException.class,
                () -> FileBackedWebhookPostgresDataSource.mountedSecret(escaping));
    }

    private Path mounted(String name, String content) throws Exception {
        Path path = temporary.resolve(name);
        Files.writeString(path, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--r-----"));
        return path;
    }
}
