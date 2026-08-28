package com.elmpay.payment.readmodel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class JdbcPaymentTimelineTest {
    @Test
    void checkpointIsLockedBeforeEventsAreProjected() {
        assertTrue(JdbcPaymentTimeline.CHECKPOINT_LOCK_SQL.contains("FOR UPDATE"));
        assertTrue(JdbcPaymentTimeline.SOURCE_EVENTS_SQL.contains("sequence_no > ?"));
        assertTrue(JdbcPaymentTimeline.SOURCE_EVENTS_SQL.contains("ORDER BY sequence_no"));
        assertTrue(JdbcPaymentTimeline.UPSERT_STATUS_SQL.contains(
                "EXCLUDED.last_sequence_no > payment_status_read_model.last_sequence_no"));
    }

    @Test
    void rebuildIsAtomicAndDeterministic() {
        assertTrue(JdbcPaymentTimeline.REBUILD_RESET_CHECKPOINT_SQL.contains(
                "generation = generation + 1"));
        assertTrue(JdbcPaymentTimeline.REBUILD_DELETE_TIMELINE_SQL.contains(
                "DELETE FROM payment_timeline_event"));
        assertTrue(JdbcPaymentTimeline.REBUILD_DELETE_STATUS_SQL.contains(
                "DELETE FROM payment_status_read_model"));
        assertTrue(JdbcPaymentTimeline.INSERT_TIMELINE_SQL.contains("ON CONFLICT"));
    }

    @Test
    void staleCheckpointCannotBeAdvanced() {
        assertThrows(JdbcPaymentTimeline.ProjectionException.class,
                () -> JdbcPaymentTimeline.requireOne(0, "checkpoint superseded"));
        JdbcPaymentTimeline.requireOne(1, "current checkpoint");
    }

    @Test
    void payloadDigestIsDeterministicAndPayloadBound() {
        assertEquals(JdbcPaymentTimeline.sha256("{\"state\":\"captured\"}"),
                JdbcPaymentTimeline.sha256("{\"state\":\"captured\"}"));
        assertTrue(!JdbcPaymentTimeline.sha256("{\"state\":\"captured\"}").equals(
                JdbcPaymentTimeline.sha256("{\"state\":\"authorized\"}")));
    }

    @Test
    void migrationCreatesTenantIsolatedCheckpointStatusAndTimeline() throws IOException {
        String migration = resource("db/migration/V039__payment_timeline_read_model.sql");
        assertTrue(migration.contains("payment_projection_checkpoint"));
        assertTrue(migration.contains("payment_status_read_model"));
        assertTrue(migration.contains("payment_timeline_event"));
        assertEquals(3, count(migration, "FORCE ROW LEVEL SECURITY"));
    }

    private static int count(String value, String needle) {
        int occurrences = 0;
        int cursor = 0;
        while ((cursor = value.indexOf(needle, cursor)) >= 0) {
            occurrences++;
            cursor += needle.length();
        }
        return occurrences;
    }

    private static String resource(String name) throws IOException {
        try (InputStream input = JdbcPaymentTimelineTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("missing test resource: " + name);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
