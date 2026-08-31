package com.elmpay.gateway;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/** Bounded reads from deployment-owned, read-only secret mounts. */
final class MountedSecretFiles {
    private static final Set<PosixFilePermission> WRITE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_WRITE);

    private MountedSecretFiles() {}

    static byte[] read(String configuredPath, String label, int maximumBytes) {
        if (configuredPath == null || configuredPath.isBlank()) {
            throw new IllegalStateException(label + " file is required");
        }
        Path path = Path.of(configuredPath).normalize();
        if (!path.isAbsolute() || maximumBytes < 1) {
            throw new IllegalStateException(label + " path must be absolute");
        }
        try {
            Path mountParent = path.getParent().toRealPath();
            Path resolved = path.toRealPath();
            if (!resolved.startsWith(mountParent)) {
                throw new IllegalStateException(label + " mount escapes its controlled directory");
            }
            if (!Files.isRegularFile(resolved)) {
                throw new IllegalStateException(label + " mount is not a regular file");
            }
            long size = Files.size(resolved);
            if (size < 1 || size > maximumBytes) {
                throw new IllegalStateException(label + " mount has an invalid size");
            }
            try {
                if (Files.getPosixFilePermissions(resolved).stream()
                        .anyMatch(WRITE_PERMISSIONS::contains)) {
                    throw new IllegalStateException(label + " mount must be read-only");
                }
            } catch (UnsupportedOperationException ignored) {
                if (Files.isWritable(resolved)) {
                    throw new IllegalStateException(label + " mount must be read-only");
                }
            }
            return Files.readAllBytes(resolved);
        } catch (IOException failure) {
            throw new IllegalStateException(label + " mount cannot be read", failure);
        }
    }

    static String readUtf8(String configuredPath, String label, int maximumBytes) {
        String value = new String(read(configuredPath, label, maximumBytes), StandardCharsets.UTF_8);
        if (value.endsWith("\r\n")) {
            value = value.substring(0, value.length() - 2);
        } else if (value.endsWith("\n")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isBlank() || value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0
                || value.indexOf('\n') >= 0) {
            throw new IllegalStateException(label + " mount has an invalid value");
        }
        return value;
    }
}
