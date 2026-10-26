package com.elmpay.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AdminDomainCommandTest {
    private static final UUID COMMAND =
            UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID TENANT =
            UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT =
            UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final Instant CREATED = Instant.parse("2026-08-30T00:00:00Z");
    private static final Instant EXPIRES = CREATED.plusSeconds(600);

    @Test
    void constructorConstantTimeChecksTheCanonicalDigest() {
        AdminDomainCommand value = command(PROJECT, AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, null);
        assertEquals(value.commandDigest(), value.expectedCommandDigest());
        assertThrows(IllegalArgumentException.class,
                () -> command(PROJECT, AdminDomainCommand.OperationCode.LIST_ADD,
                        AdminDomainCommand.ConsumerGroup.RISK, "f".repeat(64)));
    }

    @Test
    void digestAndMappingBindTenantProjectOperationAndConsumer() {
        AdminDomainCommand first = command(PROJECT, AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, null);
        AdminDomainCommand otherProject = command(UUID.randomUUID(),
                AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, null);
        assertNotEquals(first.commandDigest(), otherProject.commandDigest());
        assertThrows(IllegalArgumentException.class,
                () -> command(PROJECT, AdminDomainCommand.OperationCode.LIST_ADD,
                        AdminDomainCommand.ConsumerGroup.PAYMENT, null));
    }

    @Test
    void everyKindAcceptsOnlyItsExactOperationAndConsumerMapping() {
        assertCommand(AdminDomainCommand.Kind.CASE_CLOSE,
                AdminDomainCommand.OperationCode.CASE_CLOSE,
                AdminDomainCommand.ConsumerGroup.RISK);
        assertCommand(AdminDomainCommand.Kind.LIST_CHANGE,
                AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK);
        assertCommand(AdminDomainCommand.Kind.LIST_CHANGE,
                AdminDomainCommand.OperationCode.LIST_REMOVE,
                AdminDomainCommand.ConsumerGroup.RISK);
        assertCommand(AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.PAYMENT);
        assertCommand(AdminDomainCommand.Kind.ROLLOUT_APPROVAL,
                AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL,
                AdminDomainCommand.ConsumerGroup.ROLLOUT);

        assertInvalidMapping(AdminDomainCommand.Kind.CASE_CLOSE,
                AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK);
        assertInvalidMapping(AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.RISK);
        assertInvalidMapping(AdminDomainCommand.Kind.ROLLOUT_APPROVAL,
                AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL,
                AdminDomainCommand.ConsumerGroup.PAYMENT);
    }

    @Test
    void digestIsStableAcrossTransportRefencingAndDatabaseAssignedCreationTime() {
        String first = AdminDomainCommand.computeCommandDigest(COMMAND, TENANT, PROJECT,
                "1".repeat(64), AdminDomainCommand.Kind.LIST_CHANGE,
                AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, "6".repeat(64), "2".repeat(64),
                "3".repeat(64), 2, "4".repeat(64), "5".repeat(64), EXPIRES, 7, CREATED);
        String redispatch = AdminDomainCommand.computeCommandDigest(COMMAND, TENANT, PROJECT,
                "1".repeat(64), AdminDomainCommand.Kind.LIST_CHANGE,
                AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, "6".repeat(64), "2".repeat(64),
                "3".repeat(64), 2, "4".repeat(64), "5".repeat(64), EXPIRES, 99,
                CREATED.plusSeconds(30));
        assertEquals(first, redispatch);
    }

    @Test
    void digestRejectsMissingOrInvalidTransportMetadata() {
        assertThrows(IllegalArgumentException.class, () -> digest(0, CREATED));
        assertThrows(IllegalArgumentException.class, () -> digest(1, null));
    }

    @Test
    void queueValueRecordsEnforceClaimBoundsAndPreserveEffectFacts() {
        AdminDomainCommand value = command(PROJECT, AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, null);
        assertEquals(AdminDomainCommandQueue.EnqueueOutcome.ENQUEUED,
                new AdminDomainCommandQueue.EnqueueResult(
                        AdminDomainCommandQueue.EnqueueOutcome.ENQUEUED,
                        AdminDomainCommandQueue.State.PENDING).outcome());
        assertEquals("idempotency conflict",
                new AdminDomainCommandQueue.IdempotencyConflictException(
                        "idempotency conflict").getMessage());

        assertThrows(NullPointerException.class, () ->
                new AdminDomainCommandQueue.StoredCommand(null,
                        AdminDomainCommandQueue.State.PENDING));
        assertThrows(NullPointerException.class, () ->
                new AdminDomainCommandQueue.StoredCommand(value, null));
        AdminDomainCommandQueue.StoredCommand stored = new AdminDomainCommandQueue.StoredCommand(
                value, AdminDomainCommandQueue.State.PENDING);
        assertEquals(value, stored.command());
        assertEquals(AdminDomainCommandQueue.State.PENDING, stored.state());

        assertThrows(NullPointerException.class, () -> new AdminDomainCommandQueue.Claim(
                null, "worker-123", 1, CREATED, 1, AdminDomainCommandQueue.State.PENDING));
        assertThrows(NullPointerException.class, () -> new AdminDomainCommandQueue.Claim(
                value, "worker-123", 1, null, 1, AdminDomainCommandQueue.State.PENDING));
        assertThrows(NullPointerException.class, () -> new AdminDomainCommandQueue.Claim(
                value, "worker-123", 1, CREATED, 1, null));
        assertThrows(IllegalArgumentException.class, () -> new AdminDomainCommandQueue.Claim(
                value, "short", 1, CREATED, 1, AdminDomainCommandQueue.State.PENDING));
        assertThrows(IllegalArgumentException.class, () -> new AdminDomainCommandQueue.Claim(
                value, "worker-123", 0, CREATED, 1, AdminDomainCommandQueue.State.PENDING));
        assertThrows(IllegalArgumentException.class, () -> new AdminDomainCommandQueue.Claim(
                value, "worker-123", 1, CREATED, 0, AdminDomainCommandQueue.State.PENDING));
        assertThrows(IllegalArgumentException.class, () -> new AdminDomainCommandQueue.Claim(
                value, "worker-123", 1, CREATED, 9, AdminDomainCommandQueue.State.PENDING));
        AdminDomainCommandQueue.Claim claim = new AdminDomainCommandQueue.Claim(value,
                "worker-123", 1, CREATED.plusSeconds(30), 1,
                AdminDomainCommandQueue.State.PENDING);
        assertEquals(value, claim.command());

        AdminDomainCommandQueue.EffectReceipt receipt = new AdminDomainCommandQueue.EffectReceipt(
                COMMAND, TENANT, PROJECT, "1".repeat(64), COMMAND, "2".repeat(64),
                AdminDomainCommand.Kind.LIST_CHANGE, AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, "target-1", "3".repeat(64),
                "4".repeat(64), 2, "5".repeat(64), CREATED);
        assertEquals(TENANT, receipt.tenantId());
        assertEquals("5".repeat(64), receipt.effectDigest());
    }

    private static AdminDomainCommand command(UUID projectId,
            AdminDomainCommand.OperationCode operation,
            AdminDomainCommand.ConsumerGroup group, String overrideDigest) {
        return command(projectId, AdminDomainCommand.Kind.LIST_CHANGE, operation, group,
                overrideDigest);
    }

    private static void assertCommand(AdminDomainCommand.Kind kind,
            AdminDomainCommand.OperationCode operation,
            AdminDomainCommand.ConsumerGroup group) {
        AdminDomainCommand value = command(PROJECT, kind, operation, group, null);
        assertEquals(value.commandDigest(), value.expectedCommandDigest());
    }

    private static void assertInvalidMapping(AdminDomainCommand.Kind kind,
            AdminDomainCommand.OperationCode operation,
            AdminDomainCommand.ConsumerGroup group) {
        assertThrows(IllegalArgumentException.class,
                () -> command(PROJECT, kind, operation, group, null));
    }

    private static AdminDomainCommand command(UUID projectId, AdminDomainCommand.Kind kind,
            AdminDomainCommand.OperationCode operation,
            AdminDomainCommand.ConsumerGroup group, String overrideDigest) {
        String idempotency = "1".repeat(64);
        String proposal = "2".repeat(64);
        String policy = "3".repeat(64);
        String proposer = "4".repeat(64);
        String approver = "5".repeat(64);
        String digest = AdminDomainCommand.computeCommandDigest(COMMAND, TENANT, projectId,
                idempotency, kind, operation, group,
                "6".repeat(64), proposal, policy, 2, proposer, approver, EXPIRES, 7, CREATED);
        return new AdminDomainCommand(COMMAND, TENANT, projectId, idempotency,
                overrideDigest == null ? digest : overrideDigest,
                kind, operation, group, "6".repeat(64),
                proposal, policy, 2, proposer, approver, EXPIRES, 7, CREATED);
    }

    private static String digest(long fence, Instant createdAt) {
        return AdminDomainCommand.computeCommandDigest(COMMAND, TENANT, PROJECT,
                "1".repeat(64), AdminDomainCommand.Kind.LIST_CHANGE,
                AdminDomainCommand.OperationCode.LIST_ADD,
                AdminDomainCommand.ConsumerGroup.RISK, "6".repeat(64), "2".repeat(64),
                "3".repeat(64), 2, "4".repeat(64), "5".repeat(64), EXPIRES, fence,
                createdAt);
    }
}
