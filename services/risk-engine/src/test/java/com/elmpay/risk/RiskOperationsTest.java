package com.elmpay.risk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class RiskOperationsTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");

    @Test
    void listMutationRequiresDifferentApprover() {
        RiskOperations operations = new RiskOperations(Clock.fixed(NOW, ZoneOffset.UTC));
        RiskOperations.ApprovalRequest proposal = operations.propose(
                "tenant-a", RiskOperations.Kind.LIST_ADD, "card-fingerprint-1",
                "confirmed account takeover", "analyst-a", NOW.plusSeconds(300));

        assertThrows(SecurityException.class,
                () -> operations.approve("tenant-a", proposal.id(), "analyst-a", proposal.version()));

        RiskOperations.ApprovalRequest approved = operations.approve(
                "tenant-a", proposal.id(), "analyst-b", proposal.version());
        assertEquals(RiskOperations.Status.APPROVED, approved.status());
        assertTrue(operations.isListed("tenant-a", "card-fingerprint-1"));
        assertEquals(2, operations.auditLog().size());
        assertEquals(operations.auditLog().get(0).hash(), operations.auditLog().get(1).previousHash());
    }

    @Test
    void tenantAndOptimisticVersionAreEnforced() {
        RiskOperations operations = new RiskOperations(Clock.fixed(NOW, ZoneOffset.UTC));
        RiskOperations.ApprovalRequest proposal = operations.propose(
                "tenant-a", RiskOperations.Kind.CASE_CLOSE, "case-9",
                "merchant supplied documents", "analyst-a", NOW.plusSeconds(300));

        assertThrows(SecurityException.class,
                () -> operations.approve("tenant-b", proposal.id(), "analyst-b", proposal.version()));
        assertThrows(IllegalStateException.class,
                () -> operations.approve("tenant-a", proposal.id(), "analyst-b", 99));
    }
}
