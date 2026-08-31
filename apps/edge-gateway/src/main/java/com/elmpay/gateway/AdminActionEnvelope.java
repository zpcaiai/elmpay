package com.elmpay.gateway;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Versioned, lease-fenced command sent by the privileged admin dispatcher. */
public record AdminActionEnvelope(int schemaVersion, UUID dispatchId, UUID tenantId,
        UUID projectId, UUID approvalId, Kind kind, OperationCode operationCode,
        String targetId, String proposalDigest,
        String policyDigest, long approvalVersion, String proposerDigest,
        String approverDigest, String idempotencyKey, String workerId,
        long fencingToken, Instant leaseUntil, Instant approvalExpiresAt) {
    private static final Set<String> FIELDS = Set.of("schemaVersion", "dispatchId",
            "tenantId", "projectId", "approvalId", "kind", "operationCode", "targetId", "proposalDigest",
            "policyDigest", "approvalVersion", "proposerDigest", "approverDigest",
            "idempotencyKey", "workerId", "fencingToken", "leaseUntil",
            "approvalExpiresAt");
    private static final Pattern UUID_TEXT = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    private static final Pattern TARGET = Pattern.compile("[A-Za-z0-9._:@/-]{1,160}");
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern WORKER = Pattern.compile("[A-Za-z0-9._:-]{8,128}");

    public enum Kind {
        CASE_CLOSE,
        LIST_CHANGE,
        REFUND_OVERRIDE,
        ROLLOUT_APPROVAL
    }

    public enum OperationCode {
        CASE_CLOSE,
        LIST_ADD,
        LIST_REMOVE,
        REFUND_OVERRIDE,
        ROLLOUT_APPROVAL
    }

    public AdminActionEnvelope {
        Objects.requireNonNull(dispatchId, "dispatchId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(approvalId, "approvalId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(operationCode, "operationCode");
        Objects.requireNonNull(leaseUntil, "leaseUntil");
        Objects.requireNonNull(approvalExpiresAt, "approvalExpiresAt");
        if (schemaVersion != 2 || !dispatchId.equals(approvalId) || approvalVersion != 2
                || !TARGET.matcher(require(targetId, "targetId")).matches()
                || !digest(proposalDigest) || !digest(policyDigest)
                || !digest(proposerDigest) || !digest(approverDigest)
                || !digest(idempotencyKey) || proposerDigest.equals(approverDigest)
                || !WORKER.matcher(require(workerId, "workerId")).matches()
                || fencingToken < 1 || !leaseUntil.isBefore(approvalExpiresAt)
                || !mappingIsExact(kind, operationCode)) {
            throw new IllegalArgumentException("admin action envelope is invalid");
        }
    }

    public static AdminActionEnvelope from(Map<String, Object> value) {
        Objects.requireNonNull(value, "value");
        if (!value.keySet().equals(FIELDS)) {
            throw new IllegalArgumentException("admin action envelope fields are invalid");
        }
        return new AdminActionEnvelope(integer(value.get("schemaVersion"), "schemaVersion"),
                uuid(value.get("dispatchId"), "dispatchId"),
                uuid(value.get("tenantId"), "tenantId"),
                uuid(value.get("projectId"), "projectId"),
                uuid(value.get("approvalId"), "approvalId"),
                enumeration(value.get("kind")), operation(value.get("operationCode")),
                text(value.get("targetId"), "targetId"),
                text(value.get("proposalDigest"), "proposalDigest"),
                text(value.get("policyDigest"), "policyDigest"),
                whole(value.get("approvalVersion"), "approvalVersion"),
                text(value.get("proposerDigest"), "proposerDigest"),
                text(value.get("approverDigest"), "approverDigest"),
                text(value.get("idempotencyKey"), "idempotencyKey"),
                text(value.get("workerId"), "workerId"),
                whole(value.get("fencingToken"), "fencingToken"),
                instant(value.get("leaseUntil"), "leaseUntil"),
                instant(value.get("approvalExpiresAt"), "approvalExpiresAt"));
    }

    static Set<String> fields() {
        return FIELDS;
    }

    private static Kind enumeration(Object value) {
        try {
            return Kind.valueOf(text(value, "kind"));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("admin action kind is invalid", invalid);
        }
    }

    private static OperationCode operation(Object value) {
        try {
            return OperationCode.valueOf(text(value, "operationCode"));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("admin action operation code is invalid", invalid);
        }
    }

    private static boolean mappingIsExact(Kind kind, OperationCode operation) {
        return switch (kind) {
            case CASE_CLOSE -> operation == OperationCode.CASE_CLOSE;
            case LIST_CHANGE -> operation == OperationCode.LIST_ADD
                    || operation == OperationCode.LIST_REMOVE;
            case REFUND_OVERRIDE -> operation == OperationCode.REFUND_OVERRIDE;
            case ROLLOUT_APPROVAL -> operation == OperationCode.ROLLOUT_APPROVAL;
        };
    }

    private static UUID uuid(Object value, String field) {
        String text = text(value, field);
        if (!UUID_TEXT.matcher(text).matches()) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return UUID.fromString(text);
    }

    private static Instant instant(Object value, String field) {
        try {
            return Instant.parse(text(value, field));
        } catch (DateTimeParseException invalid) {
            throw new IllegalArgumentException(field + " is invalid", invalid);
        }
    }

    private static int integer(Object value, String field) {
        long result = whole(value, field);
        if (result < Integer.MIN_VALUE || result > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(field + " is outside int32");
        }
        return Math.toIntExact(result);
    }

    private static long whole(Object value, String field) {
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException(field + " must be an integer");
        }
        long result = number.longValue();
        if (number instanceof Float || number instanceof Double
                || number.doubleValue() != (double) result) {
            throw new IllegalArgumentException(field + " must be an integer");
        }
        return result;
    }

    private static String text(Object value, String field) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException(field + " must be text");
        }
        return text;
    }

    private static boolean digest(String value) {
        return value != null && DIGEST.matcher(value).matches();
    }

    private static String require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
