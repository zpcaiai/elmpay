package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class MountedSecretFilesTest {
    @TempDir
    Path directory;

    @Test
    void readsOnlyBoundedReadOnlySingleLineUtf8() throws Exception {
        Path secret = directory.resolve("secret");
        Files.writeString(secret, "mounted-value\n");
        Files.setPosixFilePermissions(secret, Set.of(PosixFilePermission.OWNER_READ));
        assertEquals("mounted-value",
                MountedSecretFiles.readUtf8(secret.toString(), "test secret", 64));

        Files.setPosixFilePermissions(secret, Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        assertThrows(IllegalStateException.class,
                () -> MountedSecretFiles.readUtf8(secret.toString(), "test secret", 64));
    }

    @Test
    void rejectsRelativeMissingMultilineAndOversizedValues() throws Exception {
        assertThrows(IllegalStateException.class,
                () -> MountedSecretFiles.readUtf8("relative", "test secret", 64));
        assertThrows(IllegalStateException.class,
                () -> MountedSecretFiles.readUtf8(directory.resolve("missing").toString(),
                        "test secret", 64));

        Path multiline = directory.resolve("multiline");
        Files.writeString(multiline, "one\ntwo");
        Files.setPosixFilePermissions(multiline, Set.of(PosixFilePermission.OWNER_READ));
        assertThrows(IllegalStateException.class,
                () -> MountedSecretFiles.readUtf8(multiline.toString(), "test secret", 64));

        Path oversized = directory.resolve("oversized");
        Files.writeString(oversized, "x".repeat(65));
        Files.setPosixFilePermissions(oversized, Set.of(PosixFilePermission.OWNER_READ));
        assertThrows(IllegalStateException.class,
                () -> MountedSecretFiles.readUtf8(oversized.toString(), "test secret", 64));
    }

    @Test
    void permitsInMountKubernetesRotationSymlinkButRejectsEscape() throws Exception {
        Path mount = Files.createDirectory(directory.resolve("mount"));
        Path revision = Files.createDirectory(mount.resolve("..2026_08_30"));
        Path target = revision.resolve("secret");
        Files.writeString(target, "rotated-value\n");
        Files.setPosixFilePermissions(target, Set.of(PosixFilePermission.OWNER_READ));
        Files.createSymbolicLink(mount.resolve("..data"), revision.getFileName());
        Path projected = Files.createSymbolicLink(
                mount.resolve("secret"), Path.of("..data", "secret"));
        assertEquals("rotated-value",
                MountedSecretFiles.readUtf8(projected.toString(), "test secret", 64));

        Path outside = directory.resolve("outside");
        Files.writeString(outside, "outside-value");
        Files.setPosixFilePermissions(outside, Set.of(PosixFilePermission.OWNER_READ));
        Path escaped = Files.createSymbolicLink(mount.resolve("escaped"), outside);
        assertThrows(IllegalStateException.class,
                () -> MountedSecretFiles.readUtf8(escaped.toString(), "test secret", 64));
    }
}
