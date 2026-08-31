package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class JdbcWebhookInboxStoreTest {
    @Test
    void claimIsAtomicTenantScopedSkipLockedLeaseWithMonotonicFence() {
        String sql = JdbcWebhookInboxStore.CLAIM_SQL;
        assertTrue(sql.contains("WITH candidate AS"));
        assertTrue(sql.contains("FOR UPDATE SKIP LOCKED"));
        assertTrue(sql.contains("inbox.fencing_token + 1"));
        assertTrue(sql.contains("inbox.processing_attempts + 1"));
        assertTrue(sql.contains("processing_status = 'PROCESSING'"));
        assertTrue(sql.contains("lease_expires_at <= ?::timestamptz"));
        assertTrue(sql.contains("tenant_id = ?"));
        assertTrue(sql.contains("terminal_failure = FALSE"));
    }

    @Test
    void applyAndFailureTransitionsAreFenceAndDigestGuarded() {
        assertTrue(JdbcWebhookInboxStore.TERMINALIZE_EXHAUSTED_SQL
                .contains("lease_expires_at <= ?::timestamptz"));
        assertTrue(JdbcWebhookInboxStore.TERMINALIZE_EXHAUSTED_SQL
                .contains("MAX_ATTEMPTS_EXHAUSTED"));
        assertTrue(JdbcWebhookInboxStore.LOCK_CLAIM_SQL.contains("FOR UPDATE"));
        assertTrue(JdbcWebhookInboxStore.INSERT_EFFECT_COMMIT_SQL
                .contains("ON CONFLICT (tenant_id, inbox_id) DO NOTHING"));
        assertTrue(JdbcWebhookInboxStore.MARK_PROCESSED_SQL
                .contains("lease_owner = ? AND fencing_token = ?"));
        assertTrue(JdbcWebhookInboxStore.MARK_PROCESSED_SQL
                .contains("lease_expires_at > ?::timestamptz"));
        assertTrue(JdbcWebhookInboxStore.MARK_PROCESSED_SQL
                .contains("verification_digest = ?"));
        assertTrue(JdbcWebhookInboxStore.RECORD_FAILURE_SQL
                .contains("processing_status = 'FAILED'"));
        assertTrue(JdbcWebhookInboxStore.RECORD_FAILURE_SQL
                .contains("terminal_failure = ?"));
    }

    @Test
    void migrationQuarantinesLegacyRowsAndForcesTenantRlsWithoutRawPayload()
            throws IOException {
        String base = resource("db/migration/V037__provider_webhook_inbox.sql");
        String processing = resource("db/migration/V037_1__provider_webhook_processing.sql");
        String retirement = resource("db/migration/V037_3__provider_webhook_raw_body_retirement.sql");

        assertTrue(base.contains("raw_body BYTEA"));
        assertTrue(base.contains("raw_body_sha256 CHAR(64) NOT NULL"));
        assertTrue(retirement.contains("DROP COLUMN raw_body"));
        assertTrue(processing.contains("LEGACY_VERIFICATION_DIGEST_MISSING"));
        assertTrue(processing.contains("provider_webhook_effect_commit"));
        assertTrue(processing.contains("ENABLE ROW LEVEL SECURITY"));
        assertTrue(processing.contains("FORCE ROW LEVEL SECURITY"));
        assertTrue(processing.contains("current_setting('app.tenant_id', true)"));
        assertTrue(processing.contains("provider_webhook_inbox_stale_lease_idx"));
        assertTrue(processing.contains("BEFORE UPDATE OR DELETE"));
    }

    private static String resource(String name) throws IOException {
        try (var input = JdbcWebhookInboxStoreTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            assertNotNull(input, name);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
