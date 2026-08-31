package com.elmpay.payment.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.elmpay.admin.AdminDomainCommand;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AdminDomainCommandConsumerTest {
    private static final UUID TENANT =
            UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT =
            UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID COMMAND =
            UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final UUID REFUND =
            UUID.fromString("40000000-0000-4000-8000-000000000001");
    private static final UUID INTENT =
            UUID.fromString("50000000-0000-4000-8000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void refundBindingRejectsForgedProjectProposalStateAndRequesterApproverCollision() {
        AdminDomainCommand command = refundCommand("a".repeat(64), "2".repeat(64));
        PaymentAdminDomainCommandConsumer.Binding valid = refundBinding(PROJECT,
                "a".repeat(64), "approval_pending", "requester", null);
        assertNull(PaymentAdminDomainCommandConsumer.validate(command, valid));
        assertEquals("PROJECT_BINDING_INVALID", PaymentAdminDomainCommandConsumer.validate(
                command, refundBinding(UUID.randomUUID(), "a".repeat(64),
                        "approval_pending", "requester", null)));
        assertEquals("PROPOSAL_BINDING_INVALID", PaymentAdminDomainCommandConsumer.validate(
                command, refundBinding(PROJECT, "b".repeat(64), "approval_pending",
                        "requester", null)));
        assertEquals("REFUND_STATE_INVALID", PaymentAdminDomainCommandConsumer.validate(
                command, refundBinding(PROJECT, "a".repeat(64), "succeeded",
                        "requester", null)));
        AdminDomainCommand sameActor = refundCommand("a".repeat(64), sha256("requester"));
        assertEquals("REFUND_SEPARATION_OF_DUTIES_INVALID",
                PaymentAdminDomainCommandConsumer.validate(sameActor, valid));
    }

    private static PaymentAdminDomainCommandConsumer.Binding refundBinding(UUID projectId,
            String requestDigest, String state, String requester, String approvedBy) {
        return new PaymentAdminDomainCommandConsumer.Binding(REFUND, projectId, INTENT, 1250,
                "USD", state, requestDigest, requester, approvedBy, 3);
    }

    private static AdminDomainCommand refundCommand(String proposal, String approver) {
        return command(AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.PAYMENT, REFUND.toString(), proposal,
                approver);
    }

    private static AdminDomainCommand command(AdminDomainCommand.Kind kind,
            AdminDomainCommand.OperationCode operation,
            AdminDomainCommand.ConsumerGroup group, String target, String proposal,
            String approver) {
        String idempotency = "5".repeat(64);
        String policy = "6".repeat(64);
        String proposer = "1".repeat(64);
        String digest = AdminDomainCommand.computeCommandDigest(COMMAND, TENANT, PROJECT,
                idempotency, kind, operation, group, target, proposal, policy, 2, proposer,
                approver, NOW.plusSeconds(600), 7, NOW);
        return new AdminDomainCommand(COMMAND, TENANT, PROJECT, idempotency, digest, kind,
                operation, group, target, proposal, policy, 2, proposer, approver,
                NOW.plusSeconds(600), 7, NOW);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
