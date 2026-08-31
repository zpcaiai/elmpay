package com.elmpay.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AdminActionPolicyBindingTest {
    private static final String DIGEST = "a".repeat(64);

    @Test
    void controlledRotationSymlinkLoadsAndEveryExpiryBoundaryFailsClosed(@TempDir Path root)
            throws Exception {
        Path version = Files.createDirectory(root.resolve("..2026_08_30"));
        Path policy = version.resolve("policy.json");
        Files.writeString(policy, """
                {"schemaVersion":1,"adminActionPolicyDigest":"%s",
                 "validUntil":"2026-08-30T01:15:00Z"}
                """.formatted(DIGEST));
        Files.setPosixFilePermissions(policy, PosixFilePermissions.fromString("r--r-----"));
        Files.createSymbolicLink(root.resolve("..data"), version.getFileName());
        Files.createSymbolicLink(root.resolve("policy.json"), Path.of("..data/policy.json"));

        AdminActionPolicyBinding binding = AdminActionPolicyBinding.load(
                root.resolve("policy.json").toAbsolutePath());
        AdminDomainCommand valid = command(DIGEST, Instant.parse("2026-08-30T01:10:00Z"));
        assertEquals(AdminActionPolicyBinding.Validation.VALID,
                binding.validate(valid, Instant.parse("2026-08-30T01:00:00Z")));
        assertEquals(AdminActionPolicyBinding.Validation.DIGEST_MISMATCH,
                binding.validate(command("b".repeat(64), valid.approvalExpiresAt()),
                        Instant.parse("2026-08-30T01:00:00Z")));
        assertEquals(AdminActionPolicyBinding.Validation.EXPIRED,
                binding.validate(command(DIGEST, Instant.parse("2026-08-30T01:16:00Z")),
                        Instant.parse("2026-08-30T01:00:00Z")));
    }

    @Test
    void writableOrEscapingFilesAreRejected(@TempDir Path root) throws Exception {
        Path writable = root.resolve("writable.json");
        Files.writeString(writable, "{}");
        assertThrows(IllegalStateException.class,
                () -> AdminActionPolicyBinding.load(writable.toAbsolutePath()));

        Path mount = Files.createDirectory(root.resolve("mount"));
        Path outside = root.resolve("outside.json");
        Files.writeString(outside, "{}");
        Files.setPosixFilePermissions(outside, PosixFilePermissions.fromString("r--r-----"));
        Files.createSymbolicLink(mount.resolve("policy.json"), outside);
        assertThrows(IllegalStateException.class,
                () -> AdminActionPolicyBinding.load(mount.resolve("policy.json").toAbsolutePath()));

        Path invalidUtf8 = root.resolve("invalid-utf8.json");
        Files.write(invalidUtf8, new byte[] {(byte) 0xc3, 0x28});
        Files.setPosixFilePermissions(invalidUtf8,
                PosixFilePermissions.fromString("r--r-----"));
        assertThrows(IllegalStateException.class,
                () -> AdminActionPolicyBinding.load(invalidUtf8.toAbsolutePath()));
    }

    private static AdminDomainCommand command(String policyDigest, Instant expiresAt) {
        UUID id = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        UUID tenant = UUID.fromString("11111111-1111-4111-8111-111111111111");
        UUID project = UUID.fromString("22222222-2222-4222-8222-222222222222");
        Instant created = Instant.parse("2026-08-30T01:00:00Z");
        String commandDigest = AdminDomainCommand.computeCommandDigest(id, tenant, project,
                "c".repeat(64), AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.PAYMENT, id.toString(), "d".repeat(64),
                policyDigest, 2, "e".repeat(64), "f".repeat(64), expiresAt, 7, created);
        return new AdminDomainCommand(id, tenant, project, "c".repeat(64), commandDigest,
                AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.PAYMENT, id.toString(), "d".repeat(64),
                policyDigest, 2, "e".repeat(64), "f".repeat(64), expiresAt, 7, created);
    }
}
