package com.elmpay.admin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** Immutable cross-service command created from one approved and fenced admin dispatch. */
public record AdminDomainCommand(UUID commandId, UUID tenantId, UUID projectId,
        String idempotencyKey,
        String commandDigest, Kind kind, OperationCode operationCode,
        ConsumerGroup consumerGroup, String targetId, String proposalDigest,
        String policyDigest, long approvalVersion, String proposerDigest,
        String approverDigest, Instant approvalExpiresAt,
        long sourceDispatchFencingToken, Instant createdAt) {
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern TARGET = Pattern.compile("[A-Za-z0-9._:@/-]{1,160}");

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

    public enum ConsumerGroup {
        RISK,
        PAYMENT,
        ROLLOUT
    }

    public AdminDomainCommand {
        Objects.requireNonNull(commandId, "commandId");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(operationCode, "operationCode");
        Objects.requireNonNull(consumerGroup, "consumerGroup");
        Objects.requireNonNull(approvalExpiresAt, "approvalExpiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        if (!digest(idempotencyKey) || !digest(commandDigest) || !digest(proposalDigest)
                || !digest(policyDigest) || !digest(proposerDigest) || !digest(approverDigest)
                || proposerDigest.equals(approverDigest)
                || targetId == null || !TARGET.matcher(targetId).matches()
                || approvalVersion != 2 || sourceDispatchFencingToken < 1
                || !createdAt.isBefore(approvalExpiresAt) || !mappingIsExact(kind,
                        operationCode, consumerGroup)) {
            throw new IllegalArgumentException("admin domain command is invalid");
        }
        String expected = computeCommandDigest(commandId, tenantId, projectId, idempotencyKey,
                kind, operationCode, consumerGroup, targetId, proposalDigest, policyDigest,
                approvalVersion, proposerDigest, approverDigest, approvalExpiresAt,
                sourceDispatchFencingToken, createdAt);
        if (!MessageDigest.isEqual(HexFormat.of().parseHex(commandDigest),
                HexFormat.of().parseHex(expected))) {
            throw new IllegalArgumentException("admin domain command digest is invalid");
        }
    }

    public String expectedCommandDigest() {
        return computeCommandDigest(commandId, tenantId, projectId, idempotencyKey, kind,
                operationCode, consumerGroup, targetId, proposalDigest, policyDigest,
                approvalVersion, proposerDigest, approverDigest, approvalExpiresAt,
                sourceDispatchFencingToken, createdAt);
    }

    public static String computeCommandDigest(UUID commandId, UUID tenantId, UUID projectId,
            String idempotencyKey, Kind kind, OperationCode operationCode,
            ConsumerGroup consumerGroup, String targetId, String proposalDigest,
            String policyDigest, long approvalVersion, String proposerDigest,
            String approverDigest, Instant approvalExpiresAt,
            long sourceDispatchFencingToken, Instant createdAt) {
        // Transport fencing and creation metadata are persisted as audit facts, but are not part
        // of the stable approval-bound digest: redispatch may receive a new fence or DB time.
        if (sourceDispatchFencingToken < 1 || createdAt == null) {
            throw new IllegalArgumentException("admin command transport metadata is invalid");
        }
        String canonical = "elmpay.admin-domain-command.v1\n"
                + "command_id=" + commandId + "\n"
                + "tenant_id=" + tenantId + "\n"
                + "project_id=" + projectId + "\n"
                + "idempotency_key=" + idempotencyKey + "\n"
                + "kind=" + kind + "\n"
                + "operation_code=" + operationCode + "\n"
                + "consumer_group=" + consumerGroup + "\n"
                + "target_id=" + targetId + "\n"
                + "proposal_digest=" + proposalDigest + "\n"
                + "policy_digest=" + policyDigest + "\n"
                + "approval_version=" + approvalVersion + "\n"
                + "proposer_digest=" + proposerDigest + "\n"
                + "approver_digest=" + approverDigest + "\n"
                + "approval_expires_at=" + approvalExpiresAt + "\n";
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK is missing SHA-256", impossible);
        }
    }

    private static boolean mappingIsExact(Kind kind, OperationCode operation,
            ConsumerGroup group) {
        return switch (kind) {
            case CASE_CLOSE -> operation == OperationCode.CASE_CLOSE
                    && group == ConsumerGroup.RISK;
            case LIST_CHANGE -> (operation == OperationCode.LIST_ADD
                    || operation == OperationCode.LIST_REMOVE)
                    && group == ConsumerGroup.RISK;
            case REFUND_OVERRIDE -> operation == OperationCode.REFUND_OVERRIDE
                    && group == ConsumerGroup.PAYMENT;
            case ROLLOUT_APPROVAL -> operation == OperationCode.ROLLOUT_APPROVAL
                    && group == ConsumerGroup.ROLLOUT;
        };
    }

    private static boolean digest(String value) {
        return value != null && DIGEST.matcher(value).matches();
    }
}
