package com.elmpay.scheduler;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Fail-closed authorization for destructive retention work. */
public final class RetentionGate {
    public record RetentionPolicy(String dataClass, String version, Duration minimumAge) {
        public RetentionPolicy {
            requireText(dataClass, "dataClass");
            requireText(version, "version");
            Objects.requireNonNull(minimumAge, "minimumAge");
            if (minimumAge.isNegative() || minimumAge.isZero()) {
                throw new IllegalArgumentException("minimumAge must be positive");
            }
        }
    }

    public record RetainedRecord(
            String tenantId,
            String recordId,
            String dataClass,
            Instant createdAt,
            boolean legalHold) {
        public RetainedRecord {
            requireText(tenantId, "tenantId");
            requireText(recordId, "recordId");
            requireText(dataClass, "dataClass");
            Objects.requireNonNull(createdAt, "createdAt");
        }
    }

    public record DeletionRequest(
            String tenantId,
            String recordId,
            String policyVersion,
            String requestedBy,
            String approvedBy,
            Instant approvedAt,
            String dryRunDigest) {
        public DeletionRequest {
            requireText(tenantId, "tenantId");
            requireText(recordId, "recordId");
            requireText(policyVersion, "policyVersion");
            requireText(requestedBy, "requestedBy");
            requireText(approvedBy, "approvedBy");
            Objects.requireNonNull(approvedAt, "approvedAt");
            if (requestedBy.equals(approvedBy)) {
                throw new SecurityException("destructive deletion requires four-eyes approval");
            }
            if (dryRunDigest == null || !dryRunDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("dryRunDigest must be a SHA-256 digest");
            }
        }
    }

    public record DeletionAuthorization(
            String tenantId,
            String recordId,
            String policyVersion,
            String dryRunDigest,
            Instant authorizedAt) { }

    public record DeletionReceipt(
            String tenantId,
            String recordId,
            String policyVersion,
            String dryRunDigest,
            long fencingToken,
            long deletedRecords,
            Instant completedAt,
            String backupExpiryVerifiedBy) {
        public DeletionReceipt {
            requireText(tenantId, "tenantId");
            requireText(recordId, "recordId");
            requireText(policyVersion, "policyVersion");
            if (dryRunDigest == null || !dryRunDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("dryRunDigest must be a SHA-256 digest");
            }
            if (fencingToken <= 0 || deletedRecords < 0) {
                throw new IllegalArgumentException("receipt counters are invalid");
            }
            Objects.requireNonNull(completedAt, "completedAt");
            requireText(backupExpiryVerifiedBy, "backupExpiryVerifiedBy");
        }
    }

    public DeletionAuthorization authorize(
            RetainedRecord record,
            RetentionPolicy policy,
            DeletionRequest request,
            Instant now) {
        Objects.requireNonNull(record, "record");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(now, "now");
        if (!record.tenantId().equals(request.tenantId())
                || !record.recordId().equals(request.recordId())) {
            throw new SecurityException("deletion scope does not match the retained record");
        }
        if (!record.dataClass().equals(policy.dataClass())
                || !policy.version().equals(request.policyVersion())) {
            throw new IllegalStateException("retention policy binding does not match");
        }
        if (record.legalHold()) {
            throw new IllegalStateException("legal hold blocks deletion");
        }
        if (record.createdAt().plus(policy.minimumAge()).isAfter(now)) {
            throw new IllegalStateException("minimum retention period has not elapsed");
        }
        if (request.approvedAt().isAfter(now)) {
            throw new IllegalStateException("approval timestamp is in the future");
        }
        return new DeletionAuthorization(
                record.tenantId(), record.recordId(), policy.version(), request.dryRunDigest(), now);
    }

    public void verifyReceipt(
            DeletionAuthorization authorization,
            DeletionReceipt receipt,
            String deletionExecutor,
            Instant now) {
        Objects.requireNonNull(authorization, "authorization");
        Objects.requireNonNull(receipt, "receipt");
        requireText(deletionExecutor, "deletionExecutor");
        Objects.requireNonNull(now, "now");
        if (!authorization.tenantId().equals(receipt.tenantId())
                || !authorization.recordId().equals(receipt.recordId())
                || !authorization.policyVersion().equals(receipt.policyVersion())
                || !authorization.dryRunDigest().equals(receipt.dryRunDigest())) {
            throw new SecurityException("deletion receipt is not bound to its authorization");
        }
        if (receipt.backupExpiryVerifiedBy().equals(deletionExecutor)) {
            throw new SecurityException("backup expiry requires an independent verifier");
        }
        if (receipt.completedAt().isBefore(authorization.authorizedAt())
                || receipt.completedAt().isAfter(now)) {
            throw new IllegalStateException("deletion receipt timestamp is invalid");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
