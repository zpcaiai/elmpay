package com.elmpay.scheduler.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.elmpay.admin.AdminActionPolicyBinding;
import com.elmpay.admin.AdminDomainCommand;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class RolloutAdminDomainCommandConsumerTest {
    private static final UUID TENANT =
            UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT =
            UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID COMMAND =
            UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final UUID ROLLOUT =
            UUID.fromString("60000000-0000-4000-8000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void bindingRejectsCrossProjectStaleProposalAndTerminalState() {
        RolloutAdminDomainCommandConsumer.Rollout base = rollout(PROJECT, "0".repeat(64),
                "RUNNING", 9);
        String proposal = RolloutAdminDomainCommandConsumer.proposalDigest(TENANT, base);
        RolloutAdminDomainCommandConsumer.Rollout valid = rollout(PROJECT, proposal,
                "RUNNING", 9);
        AdminDomainCommand command = command(proposal, "6".repeat(64), NOW.plusSeconds(600));
        assertNull(RolloutAdminDomainCommandConsumer.validate(command, valid));
        assertEquals("PROJECT_BINDING_INVALID", RolloutAdminDomainCommandConsumer.validate(
                command, rollout(UUID.randomUUID(), proposal, "RUNNING", 9)));
        assertEquals("PROPOSAL_BINDING_INVALID", RolloutAdminDomainCommandConsumer.validate(
                command("f".repeat(64), "6".repeat(64), NOW.plusSeconds(600)), valid));
        assertEquals("ROLLOUT_STATE_INVALID", RolloutAdminDomainCommandConsumer.validate(
                command, rollout(PROJECT, proposal, "COMPLETE", 9)));
    }

    @Test
    void governanceBindingRejectsForgedDigestAndApprovalBeyondPolicyValidity() {
        AdminActionPolicyBinding policy = new AdminActionPolicyBinding("6".repeat(64),
                NOW.plusSeconds(600));
        assertEquals(AdminActionPolicyBinding.Validation.DIGEST_MISMATCH,
                policy.validate(command("a".repeat(64), "7".repeat(64),
                        NOW.plusSeconds(500)), NOW));
        assertEquals(AdminActionPolicyBinding.Validation.EXPIRED,
                policy.validate(command("a".repeat(64), "6".repeat(64),
                        NOW.plusSeconds(601)), NOW));
    }

    @Test
    void proposalDigestBindsTenantArtifactAndRolloutFence() {
        RolloutAdminDomainCommandConsumer.Rollout first = rollout(PROJECT, "0".repeat(64),
                "RUNNING", 17);
        RolloutAdminDomainCommandConsumer.Rollout nextFence = rollout(PROJECT, "0".repeat(64),
                "RUNNING", 18);
        RolloutAdminDomainCommandConsumer.Rollout artifact = new RolloutAdminDomainCommandConsumer.Rollout(
                first.rolloutId(), first.projectId(), first.releaseBindingDigest(),
                first.targetDigest(), first.providerId(), first.region(), "e".repeat(64),
                first.previousArtifactDigest(), first.stageIndex(), first.stageStartedAt(),
                first.stageProposalDigest(), first.status(), first.fencingToken());
        String digest = RolloutAdminDomainCommandConsumer.proposalDigest(TENANT, first);
        assertNotEquals(digest,
                RolloutAdminDomainCommandConsumer.proposalDigest(TENANT, nextFence));
        assertNotEquals(digest,
                RolloutAdminDomainCommandConsumer.proposalDigest(TENANT, artifact));
        assertNotEquals(digest, RolloutAdminDomainCommandConsumer.proposalDigest(
                UUID.fromString("10000000-0000-4000-8000-000000000099"), first));
    }

    private static RolloutAdminDomainCommandConsumer.Rollout rollout(UUID projectId,
            String proposal, String status, long fence) {
        return new RolloutAdminDomainCommandConsumer.Rollout(ROLLOUT, projectId,
                "1".repeat(64), "2".repeat(64), "stripe-primary", "us-east-1",
                "3".repeat(64), "4".repeat(64), 2, NOW.minusSeconds(30), proposal, status,
                fence);
    }

    private static AdminDomainCommand command(String proposal, String policy, Instant expiresAt) {
        String idempotency = "5".repeat(64);
        String proposer = "1".repeat(64);
        String approver = "2".repeat(64);
        String digest = AdminDomainCommand.computeCommandDigest(COMMAND, TENANT, PROJECT,
                idempotency, AdminDomainCommand.Kind.ROLLOUT_APPROVAL,
                AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL,
                AdminDomainCommand.ConsumerGroup.ROLLOUT, ROLLOUT.toString(), proposal, policy,
                2, proposer, approver, expiresAt, 7, NOW);
        return new AdminDomainCommand(COMMAND, TENANT, PROJECT, idempotency, digest,
                AdminDomainCommand.Kind.ROLLOUT_APPROVAL,
                AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL,
                AdminDomainCommand.ConsumerGroup.ROLLOUT, ROLLOUT.toString(), proposal, policy,
                2, proposer, approver, expiresAt, 7, NOW);
    }
}
