package com.elmpay.gateway;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Safe idempotent acknowledgement emitted only after the governed domain effect commits. */
public record AdminActionReceipt(UUID receiptId, String idempotencyKey, UUID approvalId,
        String proposalDigest, Instant executedAt) {
    public AdminActionReceipt {
        Objects.requireNonNull(receiptId, "receiptId");
        Objects.requireNonNull(approvalId, "approvalId");
        Objects.requireNonNull(executedAt, "executedAt");
        if (idempotencyKey == null || !idempotencyKey.matches("[0-9a-f]{64}")
                || proposalDigest == null || !proposalDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("admin action receipt binding is invalid");
        }
    }

    public Map<String, Object> asJson() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schemaVersion", 1);
        value.put("receiptId", receiptId.toString());
        value.put("idempotencyKey", idempotencyKey);
        value.put("approvalId", approvalId.toString());
        value.put("proposalDigest", proposalDigest);
        value.put("status", "APPLIED");
        value.put("executedAt", executedAt.toString());
        return Map.copyOf(value);
    }
}
