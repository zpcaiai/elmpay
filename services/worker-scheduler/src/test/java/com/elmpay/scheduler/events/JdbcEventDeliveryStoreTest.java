package com.elmpay.scheduler.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class JdbcEventDeliveryStoreTest {
    @Test
    void claimUsesForUpdateSkipLockedAndMonotonicFence() {
        // The exact production SQL must contain FOR UPDATE SKIP LOCKED, not a test-only model.
        assertTrue(JdbcEventDeliveryStore.CLAIM_OUTBOX_SQL.contains("FOR UPDATE SKIP LOCKED"));
        assertTrue(JdbcEventDeliveryStore.CLAIM_OUTBOX_UPDATE_SQL.contains(
                "fencing_token = fencing_token + 1"));
        assertTrue(JdbcEventDeliveryStore.CLAIM_OUTBOX_SQL.contains(
                "prior.aggregate_revision < candidate.aggregate_revision"));
        assertTrue(JdbcEventDeliveryStore.MARK_PUBLISHED_SQL.contains("fencing_token = ?"));
        assertTrue(JdbcEventDeliveryStore.RECORD_FAILURE_SQL.contains("published_at IS NULL"));
    }

    @Test
    void staleFencingTokenCannotAcknowledge() {
        assertThrows(OutboxRelay.LeaseLostException.class,
                () -> JdbcEventDeliveryStore.requireUpdated(0,
                        "stale fencing token cannot acknowledge"));
        JdbcEventDeliveryStore.requireUpdated(1, "current fence");
    }

    @Test
    void payloadDigestIsStableAndPayloadBound() {
        assertEquals(JdbcEventDeliveryStore.sha256("{\"amount\":1}"),
                JdbcEventDeliveryStore.sha256("{\"amount\":1}"));
        assertTrue(!JdbcEventDeliveryStore.sha256("{\"amount\":1}").equals(
                JdbcEventDeliveryStore.sha256("{\"amount\":2}")));
    }

    @Test
    void migrationHasDurableInboxRlsAndRetryIndex() throws IOException {
        String migration = resource("db/migration/V012__event_delivery_runtime.sql");
        String revision = resource("db/migration/V012_1__event_envelope_revision.sql");
        assertTrue(migration.contains("consumer_event_inbox"));
        assertTrue(migration.contains("FORCE ROW LEVEL SECURITY"));
        assertTrue(migration.contains("fencing_token"));
        assertTrue(migration.contains("outbox_event_delivery_due_idx"));
        assertTrue(revision.contains("event_aggregate_revision"));
        assertTrue(revision.contains(
                "tenant_id, aggregate_type, aggregate_id, aggregate_revision"));
        assertTrue(revision.contains("consumer_inbox_aggregate_revision_unique"));
    }

    private static String resource(String name) throws IOException {
        try (InputStream input = JdbcEventDeliveryStoreTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("missing test resource: " + name);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
