package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class RetentionGateTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static final String DIGEST = "a".repeat(64);
    private final RetentionGate gate = new RetentionGate();
    private final RetentionGate.RetentionPolicy policy =
            new RetentionGate.RetentionPolicy("audit-export", "retention-4", Duration.ofDays(30));

    @Test
    void authorizesOnlyBoundFourEyesDryRun() {
        RetentionGate.DeletionAuthorization authorization = gate.authorize(
                record(false, NOW.minus(Duration.ofDays(31))), policy,
                request(), NOW);
        assertEquals("record-1", authorization.recordId());
        assertEquals(DIGEST, authorization.dryRunDigest());
    }

    @Test
    void legalHoldAndEarlyDeletionFailClosed() {
        assertThrows(IllegalStateException.class,
                () -> gate.authorize(record(true, NOW.minus(Duration.ofDays(31))), policy, request(), NOW));
        assertThrows(IllegalStateException.class,
                () -> gate.authorize(record(false, NOW.minus(Duration.ofDays(1))), policy, request(), NOW));
    }

    @Test
    void sameActorCannotConstructDeletionRequest() {
        assertThrows(SecurityException.class, () -> new RetentionGate.DeletionRequest(
                "tenant-a", "record-1", "retention-4", "operator-a", "operator-a",
                NOW.minusSeconds(10), DIGEST));
    }

    @Test
    void receiptMustBindAuthorizationAndIndependentBackupVerification() {
        RetentionGate.DeletionAuthorization authorization = gate.authorize(
                record(false, NOW.minus(Duration.ofDays(31))), policy, request(), NOW);
        RetentionGate.DeletionReceipt invalid = new RetentionGate.DeletionReceipt(
                "tenant-a", "record-1", "retention-4", DIGEST, 7, 1,
                NOW.plusSeconds(1), "worker-a");
        assertThrows(SecurityException.class,
                () -> gate.verifyReceipt(authorization, invalid, "worker-a", NOW.plusSeconds(2)));

        RetentionGate.DeletionReceipt valid = new RetentionGate.DeletionReceipt(
                "tenant-a", "record-1", "retention-4", DIGEST, 7, 1,
                NOW.plusSeconds(1), "backup-auditor");
        gate.verifyReceipt(authorization, valid, "worker-a", NOW.plusSeconds(2));
    }

    private static RetentionGate.RetainedRecord record(boolean legalHold, Instant createdAt) {
        return new RetentionGate.RetainedRecord(
                "tenant-a", "record-1", "audit-export", createdAt, legalHold);
    }

    private static RetentionGate.DeletionRequest request() {
        return new RetentionGate.DeletionRequest(
                "tenant-a", "record-1", "retention-4", "operator-a", "operator-b",
                NOW.minusSeconds(10), DIGEST);
    }
}
