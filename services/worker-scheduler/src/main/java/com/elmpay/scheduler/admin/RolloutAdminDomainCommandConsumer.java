package com.elmpay.scheduler.admin;

import com.elmpay.admin.AdminActionPolicyBinding;
import com.elmpay.admin.AdminDomainCommand;
import com.elmpay.admin.AdminDomainCommandQueue;
import com.elmpay.admin.JdbcAdminDomainCommandQueue;
import com.elmpay.payment.events.SemanticOutboxAppender;
import com.elmpay.security.CanonicalPayload;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.sql.DataSource;

/**
 * Records an internal stage approval without advancing a rollout or claiming external release
 * approval. The durable approval, semantic outbox record and command receipt commit atomically.
 */
public final class RolloutAdminDomainCommandConsumer {
    private static final String APPLY_APPROVAL_FUNCTION =
            "elmpay_apply_admin_rollout_approval(";
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

    public RolloutAdminDomainCommandConsumer(DataSource dataSource, String workerId,
            Duration lease, AdminActionPolicyBinding policy) {
        this(dataSource, new JdbcAdminDomainCommandQueue(), workerId, lease, policy);
    }

    RolloutAdminDomainCommandConsumer(DataSource dataSource,
            AdminDomainCommandQueue queue, String workerId, Duration lease,
            AdminActionPolicyBinding policy) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.queue = Objects.requireNonNull(queue, "queue");
        if (workerId == null || !WORKER.matcher(workerId).matches()
                || lease == null || lease.compareTo(Duration.ofSeconds(5)) < 0
                || lease.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("rollout admin consumer lease is invalid");
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
                        AdminDomainCommand.ConsumerGroup.ROLLOUT, workerId, lease);
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
                UUID approvalRecordId = UUID.randomUUID();
                RolloutEffect applied = applyApproval(connection, claim, approvalRecordId);
                Rollout rollout = applied.rollout();
                String failure = validate(command, rollout);
                if (failure != null) {
                    throw new SQLException("database rollout effect violated " + failure);
                }
                SemanticOutboxAppender.AppendResult event = SemanticOutboxAppender.append(
                        connection, new SemanticOutboxAppender.EventDraft(command.tenantId(),
                                command.projectId(), "rollout", rollout.rolloutId(),
                                "rollout.approval_recorded.v1", 1, applied.recordedAt(),
                                "admin:" + command.commandId(), Map.of(
                                        "rollout_id", rollout.rolloutId().toString(),
                                        "stage_index", rollout.stageIndex(),
                                        "stage_proposal_digest", command.proposalDigest(),
                                        "approval_id", command.commandId().toString(),
                                        "internal_approval_only", true)));
                String effectDigest = CanonicalPayload.sha256Hex(Map.of(
                        "command_digest", command.commandDigest(),
                        "approval_record_id", approvalRecordId.toString(),
                        "rollout_id", rollout.rolloutId().toString(),
                        "stage_index", rollout.stageIndex(),
                        "rollout_fencing_token", rollout.fencingToken(),
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
            throw new IllegalStateException("rollout admin command consumer failed", failure);
        }
    }

    private static RolloutEffect applyApproval(Connection connection,
            AdminDomainCommandQueue.Claim claim, UUID approvalRecordId) throws SQLException {
        AdminDomainCommand command = claim.command();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT rollout_id, project_id, release_binding_digest, target_digest,
                       provider_id, region, artifact_digest, previous_artifact_digest,
                       stage_index, stage_started_at, stage_proposal_digest, rollout_status,
                       rollout_fencing_token, recorded_at
                  FROM elmpay_apply_admin_rollout_approval(
                    ?::uuid, ?::uuid, ?, ?, ?::uuid)
                """)) {
            statement.setString(1, command.tenantId().toString());
            statement.setString(2, command.commandId().toString());
            statement.setString(3, claim.workerId());
            statement.setLong(4, claim.fencingToken());
            statement.setString(5, approvalRecordId.toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("rollout admin effect returned no committed row");
                }
                Rollout rollout = new Rollout(result.getObject("rollout_id", UUID.class),
                    result.getObject("project_id", UUID.class),
                    result.getString("release_binding_digest"),
                    result.getString("target_digest"), result.getString("provider_id"),
                    result.getString("region"), result.getString("artifact_digest"),
                    result.getString("previous_artifact_digest"), result.getInt("stage_index"),
                    result.getTimestamp("stage_started_at").toInstant(),
                    result.getString("stage_proposal_digest"),
                    result.getString("rollout_status"),
                    result.getLong("rollout_fencing_token"));
                return new RolloutEffect(rollout,
                        result.getTimestamp("recorded_at").toInstant());
            }
        }
    }

    static String validate(AdminDomainCommand command, Rollout rollout) {
        if (command.kind() != AdminDomainCommand.Kind.ROLLOUT_APPROVAL
                || command.operationCode()
                        != AdminDomainCommand.OperationCode.ROLLOUT_APPROVAL) {
            return "COMMAND_MAPPING_INVALID";
        }
        if (rollout == null) {
            return "ROLLOUT_NOT_FOUND";
        }
        if (!command.projectId().equals(rollout.projectId())) {
            return "PROJECT_BINDING_INVALID";
        }
        if (!"RUNNING".equals(rollout.status()) || rollout.fencingToken() < 1
                || rollout.stageIndex() < 0) {
            return "ROLLOUT_STATE_INVALID";
        }
        if (!command.proposalDigest().equals(rollout.stageProposalDigest())
                || !command.proposalDigest().equals(proposalDigest(command.tenantId(),
                        rollout))) {
            return "PROPOSAL_BINDING_INVALID";
        }
        return null;
    }

    public static String proposalDigest(UUID tenantId, Rollout rollout) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(rollout, "rollout");
        return CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("schema", "elmpay.rollout-stage-approval.v1"),
                Map.entry("tenant_id", tenantId.toString()),
                Map.entry("project_id", rollout.projectId().toString()),
                Map.entry("rollout_id", rollout.rolloutId().toString()),
                Map.entry("release_binding_digest", rollout.releaseBindingDigest()),
                Map.entry("target_digest", rollout.targetDigest()),
                Map.entry("provider_id", rollout.providerId()),
                Map.entry("region", rollout.region()),
                Map.entry("artifact_digest", rollout.artifactDigest()),
                Map.entry("previous_artifact_digest", rollout.previousArtifactDigest()),
                Map.entry("stage_index", rollout.stageIndex()),
                Map.entry("stage_started_at", rollout.stageStartedAt().toString()),
                Map.entry("status", rollout.status()),
                Map.entry("fencing_token", rollout.fencingToken())));
    }

    private void block(Connection connection, AdminDomainCommandQueue.Claim claim,
            String failureCode, Instant now) throws SQLException {
        String diagnostic = CanonicalPayload.sha256Hex(Map.of(
                "command_digest", claim.command().commandDigest(), "failure_code", failureCode));
        if (!queue.block(connection, claim, failureCode, diagnostic, now)) {
            throw new SQLException("rollout admin command block lost its fence");
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

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    public record Rollout(UUID rolloutId, UUID projectId, String releaseBindingDigest,
            String targetDigest, String providerId, String region, String artifactDigest,
            String previousArtifactDigest, int stageIndex, Instant stageStartedAt,
            String stageProposalDigest, String status, long fencingToken) { }

    private record RolloutEffect(Rollout rollout, Instant recordedAt) { }
}
