package com.elmpay.risk.runtime;

import com.elmpay.admin.AdminDomainCommand;
import com.elmpay.admin.AdminDomainCommandQueue;
import com.elmpay.events.StrictJson;
import com.elmpay.risk.CanonicalDigest;
import com.elmpay.risk.RiskRule;
import com.elmpay.risk.RuleSet;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/** Persistent four-eyes control plane for rules, list changes and case closure. */
public final class JdbcRiskControlPlane {
    public enum OperationKind { LIST_ADD, LIST_REMOVE, CASE_CLOSE }

    public record Proposal(UUID id, long version, String state, String contentDigest) { }

    private final DataSource dataSource;
    private final Clock clock;
    private final String policyDigest;
    private final String adminActionPolicyDigest;
    private final Instant adminActionPolicyValidUntil;
    private final Duration maximumApprovalWindow;

    public JdbcRiskControlPlane(DataSource dataSource, Clock clock, String policyDigest,
            Duration maximumApprovalWindow) {
        this(dataSource, clock, policyDigest, maximumApprovalWindow, policyDigest, Instant.MAX);
    }

    public JdbcRiskControlPlane(DataSource dataSource, Clock clock, String policyDigest,
            Duration maximumApprovalWindow, String adminActionPolicyDigest,
            Instant adminActionPolicyValidUntil) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.policyDigest = digest(policyDigest, "policyDigest");
        this.adminActionPolicyDigest = digest(adminActionPolicyDigest,
                "adminActionPolicyDigest");
        this.adminActionPolicyValidUntil = Objects.requireNonNull(adminActionPolicyValidUntil,
                "adminActionPolicyValidUntil");
        this.maximumApprovalWindow = Objects.requireNonNull(maximumApprovalWindow,
                "maximumApprovalWindow");
        if (maximumApprovalWindow.isZero() || maximumApprovalWindow.isNegative()
                || maximumApprovalWindow.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("approval window must be within 1ms..24h");
        }
    }

    public Proposal proposeRuleSet(String tenantId, String projectId, String version,
            Instant activatedAt, Instant expiresAt, List<RiskRule> rules, String reasonCode,
            String ticketDigest, String proposerSpiffe) {
        Instant now = clock.instant();
        requireGovernedMutation(adminActionPolicyValidUntil, now);
        if (activatedAt.isBefore(now) || !expiresAt.isAfter(activatedAt)) {
            throw new IllegalArgumentException("rule-set activation window is invalid");
        }
        RuleSet ruleSet = new RuleSet(tenantId, projectId, version, activatedAt, rules);
        UUID id = UUID.randomUUID();
        String actor = actorDigest(proposerSpiffe);
        String encodedRules = StrictJson.canonical(encodeRules(ruleSet.rules()));
        return transaction(tenantId, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO risk_runtime_rule_set
                      (proposal_id, tenant_id, project_id, rule_set_version, rules_json,
                       content_digest, policy_digest, state, proposed_by_digest, reason_code,
                       ticket_digest, proposed_at, approval_expires_at, activated_at, expires_at)
                    VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?::jsonb, ?, ?, 'PENDING', ?, ?, ?,
                            ?, ?, ?, ?)
                    """)) {
                statement.setString(1, id.toString());
                statement.setString(2, tenantId);
                statement.setString(3, projectId);
                statement.setString(4, version);
                statement.setString(5, encodedRules);
                statement.setString(6, ruleSet.digest());
                statement.setString(7, policyDigest);
                statement.setString(8, actor);
                statement.setString(9, reason(reasonCode));
                statement.setString(10, digest(ticketDigest, "ticketDigest"));
                statement.setTimestamp(11, Timestamp.from(now));
                statement.setTimestamp(12, Timestamp.from(now.plus(maximumApprovalWindow)));
                statement.setTimestamp(13, Timestamp.from(activatedAt));
                statement.setTimestamp(14, Timestamp.from(expiresAt));
                statement.executeUpdate();
            }
            audit(connection, tenantId, projectId, "RULE_SET", id, "RULE_SET_PROPOSED",
                    actor, ruleSet.digest(), now);
            return new Proposal(id, 1, "PENDING", ruleSet.digest());
        });
    }

    public Proposal approveRuleSet(String tenantId, String projectId, UUID proposalId,
            long expectedVersion, String approverSpiffe) {
        String actor = actorDigest(approverSpiffe);
        Instant now = clock.instant();
        requireGovernedMutation(adminActionPolicyValidUntil, now);
        return transaction(tenantId, connection -> {
            expireRuleSet(connection, tenantId, projectId, proposalId, now);
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE risk_runtime_rule_set
                       SET state = 'APPROVED', approved_by_digest = ?, approved_at = ?,
                           record_version = record_version + 1
                     WHERE proposal_id = ?::uuid AND tenant_id = ?::uuid AND project_id = ?::uuid
                       AND state = 'PENDING' AND record_version = ? AND policy_digest = ?
                       AND approval_expires_at > ? AND proposed_by_digest <> ?
                     RETURNING record_version, content_digest
                    """)) {
                statement.setString(1, actor);
                statement.setTimestamp(2, Timestamp.from(now));
                statement.setString(3, proposalId.toString());
                statement.setString(4, tenantId);
                statement.setString(5, projectId);
                statement.setLong(6, expectedVersion);
                statement.setString(7, policyDigest);
                statement.setTimestamp(8, Timestamp.from(now));
                statement.setString(9, actor);
                try (ResultSet row = statement.executeQuery()) {
                    if (!row.next()) throw new IllegalStateException("rule approval rejected");
                    String content = row.getString("content_digest");
                    audit(connection, tenantId, projectId, "RULE_SET", proposalId,
                            "RULE_SET_APPROVED", actor, content, now);
                    return new Proposal(proposalId, row.getLong("record_version"), "APPROVED",
                            content);
                }
            }
        });
    }

    public Proposal activateRuleSet(String tenantId, String projectId, UUID proposalId,
            long expectedVersion, String activatorSpiffe) {
        String actor = actorDigest(activatorSpiffe);
        Instant now = clock.instant();
        requireGovernedMutation(adminActionPolicyValidUntil, now);
        return transaction(tenantId, connection -> {
            try (PreparedStatement retire = connection.prepareStatement("""
                    UPDATE risk_runtime_rule_set
                       SET state = 'EXPIRED', record_version = record_version + 1
                     WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND state = 'ACTIVE'
                    """)) {
                retire.setString(1, tenantId);
                retire.setString(2, projectId);
                retire.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE risk_runtime_rule_set
                       SET state = 'ACTIVE', record_version = record_version + 1
                     WHERE proposal_id = ?::uuid AND tenant_id = ?::uuid AND project_id = ?::uuid
                       AND state = 'APPROVED' AND record_version = ? AND policy_digest = ?
                       AND activated_at <= ? AND expires_at > ?
                     RETURNING record_version, content_digest, expires_at
                    """)) {
                statement.setString(1, proposalId.toString());
                statement.setString(2, tenantId);
                statement.setString(3, projectId);
                statement.setLong(4, expectedVersion);
                statement.setString(5, policyDigest);
                statement.setTimestamp(6, Timestamp.from(now));
                statement.setTimestamp(7, Timestamp.from(now));
                try (ResultSet row = statement.executeQuery()) {
                    if (!row.next()) throw new IllegalStateException("rule activation rejected");
                    String content = row.getString("content_digest");
                    try (PreparedStatement health = connection.prepareStatement("""
                            INSERT INTO risk_runtime_capability_health
                              (capability, active_rule_set_digest, valid_until, updated_at)
                            VALUES ('risk_decision', ?, ?, ?)
                            ON CONFLICT (capability) DO UPDATE
                               SET active_rule_set_digest = EXCLUDED.active_rule_set_digest,
                                   valid_until = EXCLUDED.valid_until,
                                   updated_at = EXCLUDED.updated_at
                            """)) {
                        health.setString(1, content);
                        health.setTimestamp(2, row.getTimestamp("expires_at"));
                        health.setTimestamp(3, Timestamp.from(now));
                        health.executeUpdate();
                    }
                    audit(connection, tenantId, projectId, "RULE_SET", proposalId,
                            "RULE_SET_ACTIVATED", actor, content, now);
                    return new Proposal(proposalId, row.getLong("record_version"), "ACTIVE", content);
                }
            }
        });
    }

    public Proposal proposeOperation(String tenantId, String projectId, OperationKind kind,
            String subjectDigest, String reasonCode, String ticketDigest, String proposerSpiffe) {
        Objects.requireNonNull(kind, "kind");
        String subject = digest(subjectDigest, "subjectDigest");
        String actor = actorDigest(proposerSpiffe);
        Instant now = clock.instant();
        requireGovernedMutation(adminActionPolicyValidUntil, now);
        UUID id = UUID.randomUUID();
        String proposal = CanonicalDigest.sha256(List.of(tenantId, projectId, kind.name(), subject,
                reason(reasonCode), digest(ticketDigest, "ticketDigest"), policyDigest));
        return transaction(tenantId, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO risk_runtime_operation_request
                      (operation_id, tenant_id, project_id, kind, subject_digest, proposal_digest,
                       policy_digest, proposed_by_digest, reason_code, ticket_digest, state,
                       proposed_at, approval_expires_at)
                    VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
                    """)) {
                statement.setString(1, id.toString());
                statement.setString(2, tenantId);
                statement.setString(3, projectId);
                statement.setString(4, kind.name());
                statement.setString(5, subject);
                statement.setString(6, proposal);
                statement.setString(7, policyDigest);
                statement.setString(8, actor);
                statement.setString(9, reason(reasonCode));
                statement.setString(10, digest(ticketDigest, "ticketDigest"));
                statement.setTimestamp(11, Timestamp.from(now));
                statement.setTimestamp(12, Timestamp.from(now.plus(maximumApprovalWindow)));
                statement.executeUpdate();
            }
            audit(connection, tenantId, projectId, "OPERATION", id, "OPERATION_PROPOSED",
                    actor, proposal, now);
            return new Proposal(id, 1, "PENDING", proposal);
        });
    }

    public Proposal approveAndApplyOperation(String tenantId, String projectId, UUID operationId,
            long expectedVersion, String approverSpiffe) {
        String actor = actorDigest(approverSpiffe);
        Instant now = clock.instant();
        requireGovernedMutation(adminActionPolicyValidUntil, now);
        return transaction(tenantId, connection -> {
            expireOperation(connection, tenantId, projectId, operationId, now);
            Operation operation;
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE risk_runtime_operation_request
                       SET state = 'APPLIED', approved_by_digest = ?, applied_at = ?,
                           record_version = record_version + 1
                     WHERE operation_id = ?::uuid AND tenant_id = ?::uuid AND project_id = ?::uuid
                       AND state = 'PENDING' AND record_version = ? AND policy_digest = ?
                       AND approval_expires_at > ? AND proposed_by_digest <> ?
                     RETURNING kind, subject_digest, proposal_digest, record_version
                    """)) {
                statement.setString(1, actor);
                statement.setTimestamp(2, Timestamp.from(now));
                statement.setString(3, operationId.toString());
                statement.setString(4, tenantId);
                statement.setString(5, projectId);
                statement.setLong(6, expectedVersion);
                statement.setString(7, policyDigest);
                statement.setTimestamp(8, Timestamp.from(now));
                statement.setString(9, actor);
                try (ResultSet row = statement.executeQuery()) {
                    if (!row.next()) throw new IllegalStateException("operation approval rejected");
                    operation = new Operation(OperationKind.valueOf(row.getString("kind")),
                            row.getString("subject_digest"), row.getString("proposal_digest"),
                            row.getLong("record_version"));
                }
            }
            apply(connection, tenantId, projectId, operationId, operation, now);
            audit(connection, tenantId, projectId, "OPERATION", operationId,
                    "OPERATION_APPLIED", actor, operation.proposalDigest(), now);
            appendOperationOutbox(connection, tenantId, projectId, operationId, operation, now);
            return new Proposal(operationId, operation.version(), "APPLIED",
                    operation.proposalDigest());
        });
    }

    /**
     * Apply a previously approved admin command inside the consumer-owned transaction. The
     * caller must complete the command receipt in the same transaction after this returns.
     */
    public String applyApprovedAdminCommand(Connection connection,
            AdminDomainCommandQueue.Claim claim, Instant appliedAt) throws SQLException {
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(appliedAt, "appliedAt");
        if (connection.getAutoCommit()) {
            throw new IllegalArgumentException("admin risk effect requires a caller transaction");
        }
        AdminDomainCommand command = claim.command();
        if (command.consumerGroup() != AdminDomainCommand.ConsumerGroup.RISK
                || !Set.of(AdminDomainCommand.OperationCode.CASE_CLOSE,
                        AdminDomainCommand.OperationCode.LIST_ADD,
                        AdminDomainCommand.OperationCode.LIST_REMOVE)
                        .contains(command.operationCode())
                || !command.policyDigest().equals(adminActionPolicyDigest)
                || !adminActionPolicyValidUntil.isAfter(appliedAt)
                || command.approvalVersion() != 2
                || command.proposerDigest().equals(command.approverDigest())
                || !command.approvalExpiresAt().isAfter(appliedAt)
                || appliedAt.isAfter(claim.leaseUntil())
                || command.createdAt().isAfter(appliedAt.plusSeconds(5))
                || !command.targetId().matches("[0-9a-f]{64}")) {
            throw new AdminCommandRejectedException("risk admin command binding is invalid");
        }
        OperationKind kind = switch (command.operationCode()) {
            case CASE_CLOSE -> OperationKind.CASE_CLOSE;
            case LIST_ADD -> OperationKind.LIST_ADD;
            case LIST_REMOVE -> OperationKind.LIST_REMOVE;
            default -> throw new AdminCommandRejectedException(
                    "admin command operation is not owned by risk");
        };
        String tenantId = command.tenantId().toString();
        String projectId = command.projectId().toString();
        setTenant(connection, tenantId);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO risk_runtime_operation_request
                  (operation_id, tenant_id, project_id, kind, subject_digest, proposal_digest,
                   policy_digest, proposed_by_digest, approved_by_digest, reason_code,
                   ticket_digest, state, record_version, proposed_at, approval_expires_at,
                   applied_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, 'ADMIN_APPROVAL', ?,
                        'APPLIED', 2, ?, ?, ?)
                """)) {
            statement.setString(1, command.commandId().toString());
            statement.setString(2, tenantId);
            statement.setString(3, projectId);
            statement.setString(4, kind.name());
            statement.setString(5, command.targetId());
            statement.setString(6, command.proposalDigest());
            statement.setString(7, command.policyDigest());
            statement.setString(8, command.proposerDigest());
            statement.setString(9, command.approverDigest());
            statement.setString(10, command.idempotencyKey());
            statement.setTimestamp(11, Timestamp.from(command.createdAt()));
            statement.setTimestamp(12, Timestamp.from(command.approvalExpiresAt()));
            statement.setTimestamp(13, Timestamp.from(appliedAt));
            statement.executeUpdate();
        }
        Operation operation = new Operation(kind, command.targetId(), command.proposalDigest(), 2);
        apply(connection, tenantId, projectId, command.commandId(), operation, appliedAt);
        String effectDigest = CanonicalDigest.sha256(List.of("risk-admin-effect-v1", tenantId,
                projectId, command.commandId().toString(), command.commandDigest(),
                command.operationCode().name(), command.targetId(), command.proposalDigest(),
                command.policyDigest(), Long.toString(command.sourceDispatchFencingToken()),
                Long.toString(claim.fencingToken())));
        audit(connection, tenantId, projectId, "OPERATION", command.commandId(),
                "ADMIN_OPERATION_APPLIED", command.approverDigest(), effectDigest, appliedAt);
        appendAdminOperationOutbox(connection, command, claim, effectDigest, appliedAt);
        return effectDigest;
    }

    private static void apply(Connection connection, String tenantId, String projectId,
            UUID operationId, Operation operation, Instant now) throws SQLException {
        if (operation.kind() == OperationKind.CASE_CLOSE) {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO risk_runtime_case_resolution
                      (tenant_id, project_id, case_digest, source_operation_id, closed_at)
                    VALUES (?::uuid, ?::uuid, ?, ?::uuid, ?)
                    ON CONFLICT (tenant_id, project_id, case_digest) DO NOTHING
                    """)) {
                statement.setString(1, tenantId);
                statement.setString(2, projectId);
                statement.setString(3, operation.subjectDigest());
                statement.setString(4, operationId.toString());
                statement.setTimestamp(5, Timestamp.from(now));
                statement.executeUpdate();
            }
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO risk_runtime_list_entry
                  (tenant_id, project_id, subject_digest, source_operation_id, active, changed_at)
                VALUES (?::uuid, ?::uuid, ?, ?::uuid, ?, ?)
                ON CONFLICT (tenant_id, project_id, subject_digest) DO UPDATE
                   SET source_operation_id = EXCLUDED.source_operation_id,
                       active = EXCLUDED.active, changed_at = EXCLUDED.changed_at
                """)) {
            statement.setString(1, tenantId);
            statement.setString(2, projectId);
            statement.setString(3, operation.subjectDigest());
            statement.setString(4, operationId.toString());
            statement.setBoolean(5, operation.kind() == OperationKind.LIST_ADD);
            statement.setTimestamp(6, Timestamp.from(now));
            statement.executeUpdate();
        }
    }

    private static void appendOperationOutbox(Connection connection, String tenantId,
            String projectId, UUID operationId, Operation operation, Instant occurredAt)
            throws SQLException {
        long revision;
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO event_aggregate_revision
                  (tenant_id, aggregate_type, aggregate_id, current_revision, updated_at)
                VALUES (?::uuid, 'risk_operation', ?::uuid, 1, clock_timestamp())
                ON CONFLICT (tenant_id, aggregate_type, aggregate_id) DO UPDATE
                   SET current_revision = event_aggregate_revision.current_revision + 1,
                       updated_at = clock_timestamp()
                RETURNING current_revision
                """)) {
            statement.setString(1, tenantId);
            statement.setString(2, operationId.toString());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) throw new SQLException("operation outbox revision unavailable");
                revision = row.getLong(1);
            }
        }
        Map<String, Object> payload = Map.of("operation_id", operationId.toString(),
                "kind", operation.kind().name(), "subject_digest", operation.subjectDigest(),
                "proposal_digest", operation.proposalDigest(), "aggregate_revision", revision);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO outbox_event
                  (id, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                   event_version, aggregate_revision, payload, correlation_id, occurred_at,
                   recorded_at, trace_id, created_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, 'risk_operation', ?::uuid,
                        'risk.operation.applied.v1', 1, ?, ?::jsonb, ?, ?, clock_timestamp(), ?,
                        clock_timestamp())
                """)) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, tenantId);
            statement.setString(3, projectId);
            statement.setString(4, operationId.toString());
            statement.setLong(5, revision);
            statement.setString(6, StrictJson.canonical(payload));
            statement.setString(7, operationId.toString());
            statement.setTimestamp(8, Timestamp.from(occurredAt));
            statement.setString(9, operationId.toString());
            statement.executeUpdate();
        }
    }

    private static void appendAdminOperationOutbox(Connection connection,
            AdminDomainCommand command, AdminDomainCommandQueue.Claim claim, String effectDigest,
            Instant occurredAt) throws SQLException {
        String tenantId = command.tenantId().toString();
        String projectId = command.projectId().toString();
        long revision;
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO event_aggregate_revision
                  (tenant_id, aggregate_type, aggregate_id, current_revision, updated_at)
                VALUES (?::uuid, 'risk_operation', ?::uuid, 1, clock_timestamp())
                ON CONFLICT (tenant_id, aggregate_type, aggregate_id) DO UPDATE
                   SET current_revision = event_aggregate_revision.current_revision + 1,
                       updated_at = clock_timestamp()
                RETURNING current_revision
                """)) {
            statement.setString(1, tenantId);
            statement.setString(2, command.commandId().toString());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) throw new SQLException("admin risk outbox revision unavailable");
                revision = row.getLong(1);
            }
        }
        Map<String, Object> payload = Map.ofEntries(
                Map.entry("operation_id", command.commandId().toString()),
                Map.entry("operation_code", command.operationCode().name()),
                Map.entry("subject_digest", command.targetId()),
                Map.entry("proposal_digest", command.proposalDigest()),
                Map.entry("policy_digest", command.policyDigest()),
                Map.entry("command_digest", command.commandDigest()),
                Map.entry("effect_digest", effectDigest),
                Map.entry("source_dispatch_fencing_token",
                        command.sourceDispatchFencingToken()),
                Map.entry("consumer_fencing_token", claim.fencingToken()),
                Map.entry("aggregate_revision", revision));
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO outbox_event
                  (id, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                   event_version, aggregate_revision, payload, correlation_id, occurred_at,
                   recorded_at, trace_id, created_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, 'risk_operation', ?::uuid,
                        'risk.admin_operation.applied.v1', 1, ?, ?::jsonb, ?, ?,
                        clock_timestamp(), ?, clock_timestamp())
                """)) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, tenantId);
            statement.setString(3, projectId);
            statement.setString(4, command.commandId().toString());
            statement.setLong(5, revision);
            statement.setString(6, StrictJson.canonical(payload));
            statement.setString(7, command.commandId().toString());
            statement.setTimestamp(8, Timestamp.from(occurredAt));
            statement.setString(9, command.commandId().toString());
            statement.executeUpdate();
        }
    }

    private static void audit(Connection connection, String tenantId, String projectId,
            String aggregateType, UUID aggregateId, String event, String actor, String content,
            Instant occurredAt) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO risk_runtime_audit
                  (event_id, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                   actor_digest, content_digest, occurred_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?, ?)
                """)) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, tenantId);
            statement.setString(3, projectId);
            statement.setString(4, aggregateType);
            statement.setString(5, aggregateId.toString());
            statement.setString(6, event);
            statement.setString(7, actor);
            statement.setString(8, content);
            statement.setTimestamp(9, Timestamp.from(occurredAt));
            statement.executeUpdate();
        }
    }

    private static void expireRuleSet(Connection connection, String tenantId, String projectId,
            UUID proposalId, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE risk_runtime_rule_set SET state = 'EXPIRED', record_version = record_version + 1
                 WHERE proposal_id = ?::uuid AND tenant_id = ?::uuid AND project_id = ?::uuid
                   AND state = 'PENDING' AND approval_expires_at <= ?
                """)) {
            statement.setString(1, proposalId.toString());
            statement.setString(2, tenantId);
            statement.setString(3, projectId);
            statement.setTimestamp(4, Timestamp.from(now));
            statement.executeUpdate();
        }
    }

    private static void expireOperation(Connection connection, String tenantId, String projectId,
            UUID operationId, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE risk_runtime_operation_request
                   SET state = 'EXPIRED', record_version = record_version + 1
                 WHERE operation_id = ?::uuid AND tenant_id = ?::uuid AND project_id = ?::uuid
                   AND state = 'PENDING' AND approval_expires_at <= ?
                """)) {
            statement.setString(1, operationId.toString());
            statement.setString(2, tenantId);
            statement.setString(3, projectId);
            statement.setTimestamp(4, Timestamp.from(now));
            statement.executeUpdate();
        }
    }

    private static void setTenant(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId);
            statement.execute();
        }
    }

    private <T> T transaction(String tenantId, Work<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement tenant = connection.prepareStatement(
                        "SELECT set_config('app.tenant_id', ?, true)")) {
                    tenant.setString(1, tenantId);
                    tenant.execute();
                }
                T result = work.run(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException failure) {
                try { connection.rollback(); } catch (SQLException rollback) { failure.addSuppressed(rollback); }
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("risk control database operation failed", failure);
        }
    }

    private static List<Map<String, Object>> encodeRules(List<RiskRule> rules) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (RiskRule rule : rules) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("id", rule.id());
            value.put("version", rule.version());
            value.put("priority", rule.priority());
            value.put("signal", rule.signal());
            value.put("operator", rule.operator().name());
            value.put("threshold", rule.threshold().toPlainString());
            value.put("action", rule.action().name());
            value.put("reasonCode", rule.reasonCode());
            result.add(Map.copyOf(value));
        }
        return List.copyOf(result);
    }

    private static String actorDigest(String spiffe) {
        if (spiffe == null || !RiskCallerPolicy.canonicalSpiffe(spiffe)) {
            throw new SecurityException("actor SPIFFE identity is invalid");
        }
        return CanonicalDigest.sha256(List.of("risk-actor-v1", spiffe));
    }

    private static String digest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be a SHA-256 digest");
        }
        return value;
    }

    private static String reason(String value) {
        if (value == null || !value.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("reasonCode is invalid");
        }
        return value;
    }

    static void requireGovernedMutation(Instant validUntil, Instant now) {
        if (!Objects.requireNonNull(validUntil, "validUntil")
                .isAfter(Objects.requireNonNull(now, "now"))) {
            throw new IllegalStateException("risk governance policy is expired");
        }
    }

    private record Operation(OperationKind kind, String subjectDigest, String proposalDigest,
            long version) { }
    public static final class AdminCommandRejectedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public AdminCommandRejectedException(String message) { super(message); }
    }
    @FunctionalInterface private interface Work<T> { T run(Connection connection) throws SQLException; }
}
