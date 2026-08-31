package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.admin.AdminDomainCommand;
import com.elmpay.admin.AdminDomainCommandQueue;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class JdbcAdminActionServiceTest {
    private static final UUID TENANT =
            UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT =
            UUID.fromString("40000000-0000-4000-8000-000000000001");
    private static final UUID APPROVAL =
            UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void pendingIsNeverRepresentedAsACommittedReceipt() {
        JdbcAdminActionService.DispatchResult pending = new JdbcAdminActionService.DispatchResult(
                Optional.empty(), AdminDomainCommandQueue.State.UNKNOWN);
        assertTrue(pending.receipt().isEmpty());
        assertEquals("UNKNOWN", pending.pendingJson().get("status"));
        assertThrows(IllegalArgumentException.class,
                () -> new JdbcAdminActionService.DispatchResult(Optional.empty(),
                        AdminDomainCommandQueue.State.APPLIED));
    }

    @Test
    void commandDigestBindsProjectOperationAndFirstTransportAuditFacts() {
        String first = digest(PROJECT, AdminDomainCommand.OperationCode.REFUND_OVERRIDE, 7,
                NOW);
        assertNotEquals(first, digest(UUID.randomUUID(),
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE, 7, NOW));
        assertNotEquals(first, digest(PROJECT, AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL,
                7, NOW));
        assertEquals(first, digest(PROJECT,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE, 8, NOW));
        assertEquals(first, digest(PROJECT,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE, 7, NOW.plusMillis(1)));
    }

    private static String digest(UUID projectId, AdminDomainCommand.OperationCode operation,
            long sourceFence, Instant createdAt) {
        return AdminDomainCommand.computeCommandDigest(APPROVAL, TENANT, projectId,
                "3".repeat(64), AdminDomainCommand.Kind.REFUND_OVERRIDE, operation,
                operation == AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL
                        ? AdminDomainCommand.ConsumerGroup.ROLLOUT
                        : AdminDomainCommand.ConsumerGroup.PAYMENT,
                "30000000-0000-4000-8000-000000000001", "a".repeat(64),
                "b".repeat(64), 2, "1".repeat(64), "2".repeat(64),
                NOW.plusSeconds(600), sourceFence, createdAt);
    }

}
