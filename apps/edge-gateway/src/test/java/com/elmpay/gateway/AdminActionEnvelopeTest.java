package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AdminActionEnvelopeTest {
    @Test
    void exactVersionedLeaseFencedEnvelopeIsAccepted() {
        AdminActionEnvelope command = AdminActionEnvelope.from(valid());
        assertEquals(AdminActionEnvelope.Kind.LIST_CHANGE, command.kind());
        assertEquals(AdminActionEnvelope.OperationCode.LIST_ADD, command.operationCode());
        assertEquals(17, command.fencingToken());
        assertEquals("worker-123", command.workerId());
    }

    @Test
    void unknownFieldsDigestConfusionAndStaleLeaseShapeFailClosed() {
        Map<String, Object> unknown = new LinkedHashMap<>(valid());
        unknown.put("payload", Map.of("approve", true));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionEnvelope.from(unknown));

        Map<String, Object> sameActor = new LinkedHashMap<>(valid());
        sameActor.put("approverDigest", sameActor.get("proposerDigest"));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionEnvelope.from(sameActor));

        Map<String, Object> stale = new LinkedHashMap<>(valid());
        stale.put("leaseUntil", stale.get("approvalExpiresAt"));
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionEnvelope.from(stale));

        Map<String, Object> noFence = new LinkedHashMap<>(valid());
        noFence.put("fencingToken", 0L);
        assertThrows(IllegalArgumentException.class,
                () -> AdminActionEnvelope.from(noFence));
    }

    private static Map<String, Object> valid() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schemaVersion", 2L);
        value.put("dispatchId", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        value.put("tenantId", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        value.put("projectId", "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        value.put("approvalId", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        value.put("kind", "LIST_CHANGE");
        value.put("operationCode", "LIST_ADD");
        value.put("targetId", "c".repeat(64));
        value.put("proposalDigest", "d".repeat(64));
        value.put("policyDigest", "e".repeat(64));
        value.put("approvalVersion", 2L);
        value.put("proposerDigest", "1".repeat(64));
        value.put("approverDigest", "2".repeat(64));
        value.put("idempotencyKey", "3".repeat(64));
        value.put("workerId", "worker-123");
        value.put("fencingToken", 17L);
        value.put("leaseUntil", Instant.parse("2026-08-30T00:00:15Z").toString());
        value.put("approvalExpiresAt", Instant.parse("2026-08-30T00:10:00Z").toString());
        return Map.copyOf(value);
    }
}
