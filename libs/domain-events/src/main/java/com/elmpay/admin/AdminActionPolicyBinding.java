package com.elmpay.admin;

import com.elmpay.events.StrictJson;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Immutable, mounted governance binding independently verified by every command owner. */
public record AdminActionPolicyBinding(String policyDigest, Instant validUntil) {
    private static final int MAXIMUM_BYTES = 16_384;
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");

    public AdminActionPolicyBinding {
        if (policyDigest == null || !DIGEST.matcher(policyDigest).matches()) {
            throw new IllegalArgumentException("admin action policy digest is invalid");
        }
        Objects.requireNonNull(validUntil, "validUntil");
    }

    /**
     * Loads the shared versioned policy binding while allowing Kubernetes' controlled ..data
     * symlink rotation. The resolved file must remain inside the resolved mount directory.
     */
    public static AdminActionPolicyBinding load(Path configuredPath) {
        Objects.requireNonNull(configuredPath, "configuredPath");
        if (!configuredPath.isAbsolute()) {
            throw new IllegalStateException("admin action policy binding path must be absolute");
        }
        byte[] encoded = null;
        try {
            Path mount = configuredPath.getParent().toRealPath();
            Path resolved = configuredPath.toRealPath();
            if (!resolved.startsWith(mount) || !Files.isRegularFile(resolved,
                    LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException(
                        "admin action policy binding escaped its controlled mount");
            }
            long size = Files.size(resolved);
            if (size < 1 || size > MAXIMUM_BYTES || writable(resolved)) {
                throw new IllegalStateException(
                        "admin action policy binding must be a bounded read-only file");
            }
            encoded = Files.readAllBytes(resolved);
            if (encoded.length != size) {
                throw new IllegalStateException("admin action policy binding changed while read");
            }
            return parse(encoded);
        } catch (IOException failure) {
            throw new IllegalStateException("admin action policy binding cannot be read", failure);
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    public Validation validate(AdminDomainCommand command, Instant databaseNow) {
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(databaseNow, "databaseNow");
        if (!MessageDigest.isEqual(policyDigest.getBytes(StandardCharsets.US_ASCII),
                command.policyDigest().getBytes(StandardCharsets.US_ASCII))) {
            return Validation.DIGEST_MISMATCH;
        }
        if (!databaseNow.isBefore(validUntil)
                || !databaseNow.isBefore(command.approvalExpiresAt())
                || command.approvalExpiresAt().isAfter(validUntil)) {
            return Validation.EXPIRED;
        }
        return Validation.VALID;
    }

    private static AdminActionPolicyBinding parse(byte[] encoded) {
        Map<String, Object> value;
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString();
            value = StrictJson.object(text);
        } catch (RuntimeException | CharacterCodingException invalid) {
            throw new IllegalStateException("admin action policy binding JSON is invalid", invalid);
        }
        if (!value.keySet().equals(Set.of("schemaVersion", "adminActionPolicyDigest",
                "validUntil")) || !Long.valueOf(1).equals(value.get("schemaVersion"))
                || !(value.get("adminActionPolicyDigest") instanceof String digest)
                || !(value.get("validUntil") instanceof String expiry)) {
            throw new IllegalStateException("admin action policy binding schema is invalid");
        }
        try {
            return new AdminActionPolicyBinding(digest, Instant.parse(expiry));
        } catch (RuntimeException invalid) {
            throw new IllegalStateException("admin action policy binding values are invalid",
                    invalid);
        }
    }

    private static boolean writable(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path,
                    LinkOption.NOFOLLOW_LINKS);
            return permissions.contains(PosixFilePermission.OWNER_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE);
        } catch (UnsupportedOperationException unsupported) {
            return Files.isWritable(path);
        }
    }

    public enum Validation {
        VALID,
        DIGEST_MISMATCH,
        EXPIRED
    }
}
