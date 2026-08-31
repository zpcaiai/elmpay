package com.elmpay.payment.admin;

import com.elmpay.admin.AdminActionPolicyBinding;
import com.elmpay.admin.AdminDomainCommand;
import com.elmpay.admin.AdminDomainCommandQueue;
import com.elmpay.admin.JdbcAdminDomainCommandQueue;
import com.elmpay.payment.events.SemanticOutboxAppender;
import com.elmpay.security.CanonicalPayload;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.sql.DataSource;

/** Domain-owned, transactionally fenced consumer for approved refund overrides. */
public final class PaymentAdminDomainCommandConsumer {
    private static final Pattern WORKER = Pattern.compile("[A-Za-z0-9._:-]{8,128}");
    private final DataSource dataSource;
    private final AdminDomainCommandQueue queue;
    private final String workerId;
    private final Duration lease;
    private final AdminActionPolicyBinding policy;

    public enum Outcome {
        IDLE,
        APPLIED,
        BLOCKED
    }

    public PaymentAdminDomainCommandConsumer(DataSource dataSource, String workerId,
            Duration lease, AdminActionPolicyBinding policy) {
        this(dataSource, new JdbcAdminDomainCommandQueue(), workerId, lease, policy);
    }

    PaymentAdminDomainCommandConsumer(DataSource dataSource,
            AdminDomainCommandQueue queue, String workerId, Duration lease,
            AdminActionPolicyBinding policy) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.queue = Objects.requireNonNull(queue, "queue");
        if (workerId == null || !WORKER.matcher(workerId).matches()
                || lease == null || lease.compareTo(Duration.ofSeconds(5)) < 0
                || lease.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("payment admin consumer lease is invalid");
        }
        this.workerId = workerId;
        this.lease = lease;
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    public Outcome runOnce() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try {
                Optional<AdminDomainCommandQueue.Claim> candidate = queue.claim(connection,
                        AdminDomainCommand.ConsumerGroup.PAYMENT, workerId, lease);
                if (candidate.isEmpty()) {
                    connection.commit();
                    return Outcome.IDLE;
                }
                AdminDomainCommandQueue.Claim claim = candidate.orElseThrow();
                AdminDomainCommand command = claim.command();
                Instant now = databaseNow(connection);
                AdminActionPolicyBinding.Validation policyValidation = policy.validate(command,
                        now);
                if (policyValidation != AdminActionPolicyBinding.Validation.VALID) {
                    block(connection, claim, "ADMIN_POLICY_" + policyValidation.name(), now);
                    connection.commit();
                    return Outcome.BLOCKED;
                }
                Binding binding = binding(connection, command);
                String failure = validate(command, binding);
                if (failure != null) {
                    block(connection, claim, failure, now);
                    connection.commit();
                    return Outcome.BLOCKED;
                }

                long resultVersion = binding.version() + 1;
                String actor = "sha256:" + command.approverDigest();
                String ticket = "approval:" + command.commandId();
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE refund
                           SET state = 'approved', approved_by = ?,
                               approval_reason = 'ADMIN_DOMAIN_APPROVAL',
                               approval_ticket_id = ?, updated_at = ?, version = version + 1
                         WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND id = ?::uuid
                           AND state = 'approval_pending' AND version = ?
                           AND approved_by IS NULL AND request_digest = ?
                        """)) {
                    statement.setString(1, actor);
                    statement.setString(2, ticket);
                    statement.setTimestamp(3, Timestamp.from(now));
                    statement.setString(4, command.tenantId().toString());
                    statement.setString(5, command.projectId().toString());
                    statement.setString(6, binding.refundId().toString());
                    statement.setLong(7, binding.version());
                    statement.setString(8, command.proposalDigest());
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("refund approval lost its immutable version");
                    }
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO refund_action_receipt
                          (tenant_id, refund_id, operation, idempotency_key, request_digest,
                           actor_id, reason, ticket_id, result_version, completed_at)
                        VALUES (?::uuid, ?::uuid, 'REFUND_APPROVE', ?, ?, ?,
                                'ADMIN_DOMAIN_APPROVAL', ?, ?, ?)
                        """)) {
                    statement.setString(1, command.tenantId().toString());
                    statement.setString(2, binding.refundId().toString());
                    statement.setString(3, command.idempotencyKey());
                    statement.setString(4, command.proposalDigest());
                    statement.setString(5, actor);
                    statement.setString(6, ticket);
                    statement.setLong(7, resultVersion);
                    statement.setTimestamp(8, Timestamp.from(now));
                    statement.executeUpdate();
                }

                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("refund_id", binding.refundId().toString());
                payload.put("payment_intent_id", binding.paymentIntentId().toString());
                payload.put("amount_minor", binding.amountMinor());
                payload.put("currency", binding.currency());
                payload.put("state", "approved");
                payload.put("approval_id", command.commandId().toString());
                payload.put("approver_digest", command.approverDigest());
                SemanticOutboxAppender.AppendResult event = SemanticOutboxAppender.append(
                        connection, new SemanticOutboxAppender.EventDraft(command.tenantId(),
                                command.projectId(), "refund", binding.refundId(),
                                "refund.approved.v1", 1, now,
                                "admin:" + command.commandId(), payload));
                String effectDigest = CanonicalPayload.sha256Hex(Map.of(
                        "command_digest", command.commandDigest(),
                        "refund_id", binding.refundId().toString(),
                        "result_version", resultVersion,
                        "outbox_event_id", event.eventId().toString(),
                        "outbox_revision", event.revision()));
                queue.complete(connection, claim, effectDigest, now);
                connection.commit();
                return Outcome.APPLIED;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("payment admin command consumer failed", failure);
        }
    }

    private static Binding binding(Connection connection, AdminDomainCommand command)
            throws SQLException {
        UUID refundId;
        try {
            refundId = UUID.fromString(command.targetId());
        } catch (IllegalArgumentException invalid) {
            return null;
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, project_id, payment_intent_id, amount_minor, currency, state,
                       request_digest, requester_id, approved_by, version
                  FROM refund
                 WHERE tenant_id = ?::uuid AND id = ?::uuid
                 FOR UPDATE
                """)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, refundId.toString());
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? new Binding(result.getObject("id", UUID.class),
                        result.getObject("project_id", UUID.class),
                        result.getObject("payment_intent_id", UUID.class),
                        result.getLong("amount_minor"), result.getString("currency"),
                        result.getString("state"), result.getString("request_digest"),
                        result.getString("requester_id"), result.getString("approved_by"),
                        result.getLong("version")) : null;
            }
        }
    }

    static String validate(AdminDomainCommand command, Binding binding) {
        if (command.kind() != AdminDomainCommand.Kind.REFUND_OVERRIDE
                || command.operationCode() != AdminDomainCommand.OperationCode.REFUND_OVERRIDE) {
            return "COMMAND_MAPPING_INVALID";
        }
        if (binding == null) {
            return "REFUND_NOT_FOUND";
        }
        if (!command.projectId().equals(binding.projectId())) {
            return "PROJECT_BINDING_INVALID";
        }
        if (!command.proposalDigest().equals(binding.requestDigest())) {
            return "PROPOSAL_BINDING_INVALID";
        }
        if (!"approval_pending".equals(binding.state()) || binding.approvedBy() != null) {
            return "REFUND_STATE_INVALID";
        }
        if (binding.requesterId() == null
                || command.approverDigest().equals(sha256(binding.requesterId()))) {
            return "REFUND_SEPARATION_OF_DUTIES_INVALID";
        }
        return null;
    }

    private void block(Connection connection, AdminDomainCommandQueue.Claim claim,
            String failureCode, Instant now) throws SQLException {
        String diagnostic = CanonicalPayload.sha256Hex(Map.of(
                "command_digest", claim.command().commandDigest(), "failure_code", failureCode));
        if (!queue.block(connection, claim, failureCode, diagnostic, now)) {
            throw new SQLException("payment admin command block lost its fence");
        }
    }

    private static Instant databaseNow(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT clock_timestamp()"); ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("database clock returned no value");
            }
            return result.getTimestamp(1).toInstant();
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK is missing SHA-256", impossible);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    static record Binding(UUID refundId, UUID projectId, UUID paymentIntentId,
            long amountMinor, String currency, String state, String requestDigest,
            String requesterId, String approvedBy, long version) { }
}
