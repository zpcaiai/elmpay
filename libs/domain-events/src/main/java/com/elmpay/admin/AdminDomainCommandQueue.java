package com.elmpay.admin;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Caller-owned transaction port shared by edge enqueue and domain-owned consumers. */
public interface AdminDomainCommandQueue {
    final class IdempotencyConflictException extends SQLException {
        private static final long serialVersionUID = 1L;

        public IdempotencyConflictException(String message) {
            super(message);
        }
    }

    enum State {
        PENDING,
        CLAIMED,
        RETRY,
        UNKNOWN,
        APPLIED,
        BLOCKED
    }

    enum EnqueueOutcome {
        ENQUEUED,
        EXISTING
    }

    record EnqueueResult(EnqueueOutcome outcome, State state) { }

    record StoredCommand(AdminDomainCommand command, State state) {
        public StoredCommand {
            java.util.Objects.requireNonNull(command, "command");
            java.util.Objects.requireNonNull(state, "state");
        }
    }

    record Claim(AdminDomainCommand command, String workerId, long fencingToken,
            Instant leaseUntil, int attempt, State previousState) {
        public Claim {
            java.util.Objects.requireNonNull(command, "command");
            java.util.Objects.requireNonNull(leaseUntil, "leaseUntil");
            java.util.Objects.requireNonNull(previousState, "previousState");
            if (workerId == null || !workerId.matches("[A-Za-z0-9._:-]{8,128}")
                    || fencingToken < 1 || attempt < 1 || attempt > 8) {
                throw new IllegalArgumentException("admin command claim is invalid");
            }
        }
    }

    record EffectReceipt(UUID receiptId, UUID tenantId, UUID projectId,
            String idempotencyKey,
            UUID approvalId, String commandDigest, AdminDomainCommand.Kind kind,
            AdminDomainCommand.OperationCode operationCode,
            AdminDomainCommand.ConsumerGroup consumerGroup, String targetId,
            String proposalDigest, String policyDigest, long consumerFencingToken,
            String effectDigest, Instant executedAt) { }

    EnqueueResult enqueue(Connection connection, AdminDomainCommand command)
            throws SQLException;

    Optional<StoredCommand> findCommand(Connection connection, UUID tenantId,
            String idempotencyKey) throws SQLException;

    Optional<Claim> claim(Connection connection,
            AdminDomainCommand.ConsumerGroup consumerGroup, String workerId,
            Duration lease) throws SQLException;

    EffectReceipt complete(Connection connection, Claim claim, String effectDigest,
            Instant executedAt) throws SQLException;

    boolean retry(Connection connection, Claim claim, String failureCode,
            String diagnosticDigest, Instant nextAttemptAt, boolean outcomeUnknown,
            Instant updatedAt) throws SQLException;

    boolean block(Connection connection, Claim claim, String failureCode,
            String diagnosticDigest, Instant updatedAt) throws SQLException;

    Optional<EffectReceipt> findReceipt(Connection connection, UUID tenantId,
            String idempotencyKey) throws SQLException;

    /** Edge-only tenant-scoped observer used by admin-web polling across owner groups. */
    Optional<EffectReceipt> observeReceipt(Connection connection, AdminDomainCommand command)
            throws SQLException;
}
