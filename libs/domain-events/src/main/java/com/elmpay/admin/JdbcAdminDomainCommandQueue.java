package com.elmpay.admin;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * PostgreSQL adapter backed only by the narrow elmpay.admin-command-db-api.v1 functions.
 * Runtime roles intentionally have no direct command, signal, or effect-receipt table DML.
 */
public final class JdbcAdminDomainCommandQueue implements AdminDomainCommandQueue {
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern FAILURE = Pattern.compile("[A-Z][A-Z0-9_]{2,63}");
    private static final Pattern WORKER = Pattern.compile("[A-Za-z0-9._:-]{8,128}");

    @Override
    public EnqueueResult enqueue(Connection connection, AdminDomainCommand command)
            throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(command, "command");
        setTenant(connection, command.tenantId());
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT outcome, command_state
                  FROM elmpay_admin_enqueue_command(
                    ?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, command.commandId().toString());
            statement.setString(2, command.tenantId().toString());
            statement.setString(3, command.projectId().toString());
            statement.setString(4, command.idempotencyKey());
            statement.setString(5, command.commandDigest());
            statement.setString(6, command.kind().name());
            statement.setString(7, command.operationCode().name());
            statement.setString(8, command.consumerGroup().name());
            statement.setString(9, command.targetId());
            statement.setString(10, command.proposalDigest());
            statement.setString(11, command.policyDigest());
            statement.setLong(12, command.approvalVersion());
            statement.setString(13, command.proposerDigest());
            statement.setString(14, command.approverDigest());
            statement.setTimestamp(15, Timestamp.from(command.approvalExpiresAt()));
            statement.setLong(16, command.sourceDispatchFencingToken());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("admin command enqueue returned no outcome");
                }
                try {
                    return new EnqueueResult(EnqueueOutcome.valueOf(result.getString(1)),
                            State.valueOf(result.getString(2)));
                } catch (IllegalArgumentException invalid) {
                    throw new SQLException("admin command enqueue returned an invalid state",
                            invalid);
                }
            }
        } catch (SQLException failure) {
            if ("23505".equals(failure.getSQLState())) {
                throw new IdempotencyConflictException(
                        "admin command idempotency key conflicts with another binding");
            }
            throw failure;
        }
    }

    @Override
    public Optional<StoredCommand> findCommand(Connection connection, UUID tenantId,
            String idempotencyKey) throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(tenantId, "tenantId");
        requireDigest(idempotencyKey, "idempotency key");
        setTenant(connection, tenantId);
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT command_id, project_id, idempotency_key, command_digest, kind,
                       operation_code, consumer_group, target_id, proposal_digest,
                       policy_digest, approval_version, proposer_digest, approver_digest,
                       approval_expires_at, source_dispatch_fencing_token, created_at,
                       command_state
                  FROM elmpay_admin_observe_command(?::uuid, ?)
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, idempotencyKey);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return Optional.empty();
                }
                return Optional.of(new StoredCommand(command(result, tenantId),
                        parseState(result.getString("command_state"))));
            }
        }
    }

    @Override
    public Optional<Claim> claim(Connection connection,
            AdminDomainCommand.ConsumerGroup requestedGroup, String workerId, Duration lease)
            throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(requestedGroup, "requestedGroup");
        Objects.requireNonNull(lease, "lease");
        if (workerId == null || !WORKER.matcher(workerId).matches()
                || lease.compareTo(Duration.ofSeconds(5)) < 0
                || lease.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("admin command consumer lease is invalid");
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT command_id, tenant_id, project_id, idempotency_key, command_digest,
                       kind, operation_code, consumer_group, target_id, proposal_digest,
                       policy_digest, approval_version, proposer_digest, approver_digest,
                       approval_expires_at, source_dispatch_fencing_token, created_at,
                       lease_until, consumer_fencing_token, attempt, previous_state
                  FROM elmpay_admin_claim_command(?, ?)
                """)) {
            statement.setString(1, workerId);
            statement.setLong(2, lease.toMillis());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return Optional.empty();
                }
                UUID tenantId = result.getObject("tenant_id", UUID.class);
                AdminDomainCommand command = command(result, tenantId);
                if (command.consumerGroup() != requestedGroup) {
                    throw new SQLException(
                            "database role is not bound to requested consumer group");
                }
                return Optional.of(new Claim(command, workerId,
                        result.getLong("consumer_fencing_token"),
                        result.getTimestamp("lease_until").toInstant(),
                        result.getInt("attempt"), parseState(result.getString("previous_state"))));
            }
        }
    }

    @Override
    public EffectReceipt complete(Connection connection, Claim claim, String effectDigest,
            Instant ignoredCallerExecutedAt) throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(ignoredCallerExecutedAt, "executedAt");
        requireDigest(effectDigest, "effect digest");
        AdminDomainCommand command = claim.command();
        setTenant(connection, command.tenantId());
        UUID receiptId = UUID.randomUUID();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT receipt_id, tenant_id, project_id, idempotency_key, approval_id,
                       command_digest, kind, operation_code, consumer_group, target_id,
                       proposal_digest, policy_digest, consumer_fencing_token, effect_digest,
                       executed_at
                  FROM elmpay_admin_complete_command(
                    ?::uuid, ?::uuid, ?, ?, ?::uuid, ?)
                """)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.commandId().toString());
            statement.setString(3, claim.workerId());
            statement.setLong(4, claim.fencingToken());
            statement.setString(5, receiptId.toString());
            statement.setString(6, effectDigest);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("admin command completion returned no receipt");
                }
                EffectReceipt receipt = receipt(result, command.tenantId(),
                        command.idempotencyKey());
                requireReceiptBinding(receipt, claim, effectDigest);
                return receipt;
            }
        }
    }

    @Override
    public boolean retry(Connection connection, Claim claim, String failureCode,
            String diagnosticDigest, Instant nextAttemptAt, boolean outcomeUnknown,
            Instant ignoredCallerUpdatedAt) throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(claim, "claim");
        requireFailure(failureCode, diagnosticDigest);
        Objects.requireNonNull(nextAttemptAt, "nextAttemptAt");
        Objects.requireNonNull(ignoredCallerUpdatedAt, "updatedAt");
        AdminDomainCommand command = claim.command();
        setTenant(connection, command.tenantId());
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT elmpay_admin_retry_command(
                    ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.commandId().toString());
            statement.setString(3, claim.workerId());
            statement.setLong(4, claim.fencingToken());
            statement.setString(5, failureCode);
            statement.setString(6, diagnosticDigest);
            statement.setTimestamp(7, Timestamp.from(nextAttemptAt));
            statement.setBoolean(8, outcomeUnknown);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        }
    }

    @Override
    public boolean block(Connection connection, Claim claim, String failureCode,
            String diagnosticDigest, Instant ignoredCallerUpdatedAt) throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(claim, "claim");
        requireFailure(failureCode, diagnosticDigest);
        Objects.requireNonNull(ignoredCallerUpdatedAt, "updatedAt");
        AdminDomainCommand command = claim.command();
        setTenant(connection, command.tenantId());
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT elmpay_admin_block_command(?::uuid, ?::uuid, ?, ?, ?, ?)
                """)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.commandId().toString());
            statement.setString(3, claim.workerId());
            statement.setLong(4, claim.fencingToken());
            statement.setString(5, failureCode);
            statement.setString(6, diagnosticDigest);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        }
    }

    @Override
    public Optional<EffectReceipt> findReceipt(Connection connection, UUID tenantId,
            String idempotencyKey) throws SQLException {
        // Keep the exact governed database API name visible at this boundary for static contract
        // verification; receiptThrough still centralizes tenant and transaction checks.
        String governedFunction = "elmpay_admin_find_effect_receipt(";
        return receiptThrough(connection, tenantId, idempotencyKey,
                governedFunction.substring(0, governedFunction.length() - 1));
    }

    @Override
    public Optional<EffectReceipt> observeReceipt(Connection connection,
            AdminDomainCommand command) throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(command, "command");
        setTenant(connection, command.tenantId());
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT receipt_id, project_id, approval_id, command_digest, kind,
                       operation_code, consumer_group, target_id, proposal_digest,
                       policy_digest, consumer_fencing_token, effect_digest, executed_at
                  FROM elmpay_admin_observe_effect_receipt(
                    ?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.projectId().toString());
            statement.setString(3, command.idempotencyKey());
            statement.setString(4, command.commandId().toString());
            statement.setString(5, command.commandDigest());
            statement.setString(6, command.kind().name());
            statement.setString(7, command.operationCode().name());
            statement.setString(8, command.consumerGroup().name());
            statement.setString(9, command.targetId());
            statement.setString(10, command.proposalDigest());
            statement.setString(11, command.policyDigest());
            statement.setLong(12, command.approvalVersion());
            statement.setString(13, command.proposerDigest());
            statement.setString(14, command.approverDigest());
            statement.setTimestamp(15, Timestamp.from(command.approvalExpiresAt()));
            statement.setLong(16, command.sourceDispatchFencingToken());
            try (ResultSet result = statement.executeQuery()) {
                return result.next()
                        ? Optional.of(receipt(result, command.tenantId(),
                                command.idempotencyKey()))
                        : Optional.empty();
            }
        }
    }

    private static Optional<EffectReceipt> receiptThrough(Connection connection, UUID tenantId,
            String idempotencyKey, String function) throws SQLException {
        requireCallerTransaction(connection);
        Objects.requireNonNull(tenantId, "tenantId");
        requireDigest(idempotencyKey, "idempotency key");
        setTenant(connection, tenantId);
        String sql = """
                SELECT receipt_id, project_id, approval_id, command_digest, kind,
                       operation_code, consumer_group, target_id, proposal_digest,
                       policy_digest, consumer_fencing_token, effect_digest, executed_at
                  FROM %s(?::uuid, ?)
                """.formatted(function);
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, idempotencyKey);
            try (ResultSet result = statement.executeQuery()) {
                return result.next()
                        ? Optional.of(receipt(result, tenantId, idempotencyKey))
                        : Optional.empty();
            }
        }
    }

    private static AdminDomainCommand command(ResultSet result, UUID tenantId)
            throws SQLException {
        try {
            return new AdminDomainCommand(result.getObject("command_id", UUID.class), tenantId,
                    result.getObject("project_id", UUID.class),
                    result.getString("idempotency_key"), result.getString("command_digest"),
                    AdminDomainCommand.Kind.valueOf(result.getString("kind")),
                    AdminDomainCommand.OperationCode.valueOf(result.getString("operation_code")),
                    AdminDomainCommand.ConsumerGroup.valueOf(result.getString("consumer_group")),
                    result.getString("target_id"), result.getString("proposal_digest"),
                    result.getString("policy_digest"), result.getLong("approval_version"),
                    result.getString("proposer_digest"), result.getString("approver_digest"),
                    result.getTimestamp("approval_expires_at").toInstant(),
                    result.getLong("source_dispatch_fencing_token"),
                    result.getTimestamp("created_at").toInstant());
        } catch (IllegalArgumentException invalid) {
            throw new SQLException("stored admin command failed canonical validation", invalid);
        }
    }

    private static EffectReceipt receipt(ResultSet result, UUID tenantId, String idempotencyKey)
            throws SQLException {
        try {
            return new EffectReceipt(result.getObject("receipt_id", UUID.class), tenantId,
                    result.getObject("project_id", UUID.class), idempotencyKey,
                    result.getObject("approval_id", UUID.class),
                    result.getString("command_digest"),
                    AdminDomainCommand.Kind.valueOf(result.getString("kind")),
                    AdminDomainCommand.OperationCode.valueOf(result.getString("operation_code")),
                    AdminDomainCommand.ConsumerGroup.valueOf(result.getString("consumer_group")),
                    result.getString("target_id"), result.getString("proposal_digest"),
                    result.getString("policy_digest"),
                    result.getLong("consumer_fencing_token"), result.getString("effect_digest"),
                    result.getTimestamp("executed_at").toInstant());
        } catch (IllegalArgumentException invalid) {
            throw new SQLException("stored admin receipt failed canonical validation", invalid);
        }
    }

    private static void requireReceiptBinding(EffectReceipt receipt, Claim claim,
            String effectDigest) throws SQLException {
        AdminDomainCommand command = claim.command();
        if (!receipt.tenantId().equals(command.tenantId())
                || !receipt.projectId().equals(command.projectId())
                || !receipt.idempotencyKey().equals(command.idempotencyKey())
                || !receipt.approvalId().equals(command.commandId())
                || !receipt.commandDigest().equals(command.commandDigest())
                || receipt.kind() != command.kind()
                || receipt.operationCode() != command.operationCode()
                || receipt.consumerGroup() != command.consumerGroup()
                || !receipt.targetId().equals(command.targetId())
                || !receipt.proposalDigest().equals(command.proposalDigest())
                || !receipt.policyDigest().equals(command.policyDigest())
                || receipt.consumerFencingToken() != claim.fencingToken()
                || !receipt.effectDigest().equals(effectDigest)) {
            throw new SQLException("admin command completion returned a mismatched receipt");
        }
    }

    private static State parseState(String state) throws SQLException {
        try {
            return State.valueOf(state);
        } catch (IllegalArgumentException invalid) {
            throw new SQLException("database returned an unknown admin command state", invalid);
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static void requireCallerTransaction(Connection connection) throws SQLException {
        Objects.requireNonNull(connection, "connection");
        if (connection.getAutoCommit()) {
            throw new IllegalArgumentException("admin command queue requires caller transaction");
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('search_path', 'pg_catalog,public,pg_temp', true)")) {
            statement.execute();
        }
    }

    private static void requireFailure(String code, String digest) {
        if (code == null || !FAILURE.matcher(code).matches()) {
            throw new IllegalArgumentException("admin command failure code is invalid");
        }
        requireDigest(digest, "diagnostic digest");
    }

    private static void requireDigest(String value, String label) {
        if (value == null || !DIGEST.matcher(value).matches()) {
            throw new IllegalArgumentException(label + " is invalid");
        }
    }
}
