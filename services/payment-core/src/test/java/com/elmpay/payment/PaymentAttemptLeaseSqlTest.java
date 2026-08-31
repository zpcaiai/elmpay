package com.elmpay.payment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class PaymentAttemptLeaseSqlTest {
    @Test
    void recoveryClaimLocksOnlyExpiredUnresolvedMoneyAttempts() {
        String claim = JdbcPaymentRepository.CLAIM_RECOVERABLE_ATTEMPT_SQL;
        assertTrue(claim.contains("operation <> 'query'"));
        assertTrue(claim.contains("lease_expires_at <= ?"));
        assertTrue(claim.contains("FOR UPDATE SKIP LOCKED"));
        assertTrue(claim.contains("ORDER BY sequence DESC"));
    }

    @Test
    void claimUpdateIsOwnerAndFenceBound() {
        String update = JdbcPaymentRepository.FENCED_ATTEMPT_UPDATE_SQL;
        assertTrue(update.contains("fencing_token = fencing_token + 1"));
        assertTrue(update.contains("lease_owner = ? AND fencing_token = ?"));
    }

    @Test
    void migrationBackfillsAndConstrainsLeaseState() throws IOException {
        String migration = resource("db/migration/V036_1__payment_attempt_leases.sql");
        assertTrue(migration.contains("legacy:' || id::text"));
        assertTrue(migration.contains("fencing_token > 0"));
        assertTrue(migration.contains("lease_expires_at >= started_at"));
        assertTrue(migration.contains("payment_attempt_recovery_lease_idx"));
        assertTrue(migration.contains("CREATE TRIGGER payment_attempt_final_guard"));
    }

    private static String resource(String name) throws IOException {
        try (InputStream input = PaymentAttemptLeaseSqlTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("missing test resource: " + name);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
