package com.elmpay.gateway;

import com.elmpay.admin.AdminDomainCommand;
import com.elmpay.admin.AdminDomainCommandQueue;
import com.elmpay.admin.JdbcAdminDomainCommandQueue;
import com.elmpay.security.CanonicalPayload;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.sql.DataSource;

/**
 * Durable admin ingress. This boundary validates the approval and dispatcher fence, then only
 * enqueues an immutable owner-routed command. Domain tables are changed exclusively by their
 * owning consumers, which append the effect receipt in the same caller-owned transaction.
 */
public final class JdbcAdminActionService {
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SERVICE = Pattern.compile("[a-z][a-z0-9-]{1,62}");
    private static final Map<AdminActionEnvelope.Kind, PolicyBinding> POLICY = Map.of(
            AdminActionEnvelope.Kind.CASE_CLOSE,
            new PolicyBinding("risk_decision.override", "risk_decision"),
            AdminActionEnvelope.Kind.LIST_CHANGE,
            new PolicyBinding("risk_rule.write", "risk_rule"),
            AdminActionEnvelope.Kind.REFUND_OVERRIDE,
            new PolicyBinding("refund.approve", "refund"),
            AdminActionEnvelope.Kind.ROLLOUT_APPROVAL,
            new PolicyBinding("config.write", "config"));
    private static final Set<String> REQUIRED_TABLES = Set.of("admin_approval",
            "admin_action_dispatch", "admin_diagnostic_snapshot", "admin_domain_command",
            "admin_domain_command_signal", "admin_action_effect_receipt",
            "admin_action_diagnostic_audit");
    private static final Set<String> FORCE_RLS_TABLES = Set.of("admin_approval",
            "admin_action_dispatch", "admin_diagnostic_snapshot", "admin_domain_command",
            "admin_domain_command_signal", "admin_action_effect_receipt",
            "admin_action_diagnostic_audit");

    private final DataSource dataSource;
    private final JdbcAdminDomainCommandQueue queue;

    public record DispatchResult(Optional<AdminActionReceipt> receipt,
            AdminDomainCommandQueue.State state) {
        public DispatchResult {
            Objects.requireNonNull(receipt, "receipt");
            Objects.requireNonNull(state, "state");
            if ((state == AdminDomainCommandQueue.State.APPLIED) != receipt.isPresent()) {
                throw new IllegalArgumentException("admin dispatch result is inconsistent");
            }
        }

        public Map<String, Object> pendingJson() {
            return Map.of("schemaVersion", 1, "status", state.name());
        }
    }

    public record LookupResult(Optional<AdminActionReceipt> receipt,
            Optional<AdminDomainCommandQueue.State> state) {
        public LookupResult {
            Objects.requireNonNull(receipt, "receipt");
            Objects.requireNonNull(state, "state");
            if (receipt.isPresent() && state.orElse(null) != AdminDomainCommandQueue.State.APPLIED) {
                throw new IllegalArgumentException("admin lookup result is inconsistent");
            }
        }
    }

    public JdbcAdminActionService(DataSource dataSource) {
        this(dataSource, new JdbcAdminDomainCommandQueue());
    }

    JdbcAdminActionService(DataSource dataSource, JdbcAdminDomainCommandQueue queue) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.queue = Objects.requireNonNull(queue, "queue");
    }

    public DispatchResult dispatch(AdminActionEnvelope envelope) {
        Objects.requireNonNull(envelope, "envelope");
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, envelope.tenantId());
                Optional<ExistingCommand> observed = existingCommand(connection, envelope);
                if (observed.isPresent()) {
                    Optional<AdminDomainCommandQueue.EffectReceipt> replay =
                            queue.observeReceipt(connection, observed.orElseThrow().command());
                    if (replay.isPresent()) {
                        if (observed.orElseThrow().state()
                            != AdminDomainCommandQueue.State.APPLIED) {
                            throw rejected("EFFECT_RECEIPT_ORPHANED",
                                    "admin effect receipt has no applied command binding");
                        }
                        requireReplay(replay.orElseThrow(), envelope,
                                observed.orElseThrow().command());
                        connection.commit();
                        return new DispatchResult(Optional.of(toReceipt(replay.orElseThrow())),
                                AdminDomainCommandQueue.State.APPLIED);
                    }
                }

                Instant now = databaseNow(connection);
                DispatchClaim claim = lockDispatch(connection, envelope.idempotencyKey());
                requireLiveClaim(envelope, claim, now);
                Approval approval = lockApproval(connection, envelope.approvalId());
                requireApproval(envelope, approval, now);
                Optional<ExistingCommand> existing = existingCommand(
                        connection, envelope);
                if (existing.isPresent()) {
                    if (existing.orElseThrow().state()
                            == AdminDomainCommandQueue.State.APPLIED) {
                        throw rejected("EFFECT_RECEIPT_MISSING",
                                "applied admin command has no committed effect receipt");
                    }
                    connection.commit();
                    return new DispatchResult(Optional.empty(), existing.orElseThrow().state());
                }
                AdminDomainCommand command = command(envelope, now);
                AdminDomainCommandQueue.EnqueueResult result = queue.enqueue(connection, command);
                if (result.state() == AdminDomainCommandQueue.State.APPLIED) {
                    throw rejected("EFFECT_RECEIPT_MISSING",
                            "applied admin command has no committed effect receipt");
                }
                connection.commit();
                return new DispatchResult(Optional.empty(), result.state());
            } catch (AdminDomainCommandQueue.IdempotencyConflictException conflict) {
                rollback(connection, conflict);
                throw rejected("IDEMPOTENCY_CONFLICT",
                        "admin command idempotency key belongs to another binding");
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new AdminActionException("ADMIN_ACTION_DATABASE_UNAVAILABLE",
                    "admin action database is unavailable", failure);
        }
    }

    public Optional<AdminActionReceipt> findReceipt(UUID tenantId, String idempotencyKey) {
        return lookup(tenantId, idempotencyKey).receipt();
    }

    public LookupResult lookup(UUID tenantId, String idempotencyKey) {
        requireDigest(idempotencyKey, "idempotency key");
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, Objects.requireNonNull(tenantId, "tenantId"));
                Optional<AdminDomainCommandQueue.StoredCommand> stored = queue.findCommand(
                        connection, tenantId, idempotencyKey);
                Optional<AdminDomainCommandQueue.EffectReceipt> receiptByKey =
                        queue.findReceipt(connection, tenantId, idempotencyKey);
                Optional<AdminActionReceipt> receipt = stored.isEmpty()
                        ? receiptByKey.map(JdbcAdminActionService::toReceipt)
                        : queue.observeReceipt(connection, stored.orElseThrow().command())
                                .map(JdbcAdminActionService::toReceipt);
                Optional<AdminDomainCommandQueue.State> state = stored.map(
                        AdminDomainCommandQueue.StoredCommand::state);
                if (receipt.isPresent()
                        && state.orElse(null) != AdminDomainCommandQueue.State.APPLIED) {
                    throw rejected("EFFECT_RECEIPT_ORPHANED",
                            "admin effect receipt has no applied command binding");
                }
                connection.commit();
                return new LookupResult(receipt, state);
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new AdminActionException("ADMIN_ACTION_DATABASE_UNAVAILABLE",
                    "admin action receipt store is unavailable", failure);
        }
    }

    public Map<String, Object> diagnostic(UUID tenantId, String service,
            String operatorSubjectDigest) {
        Objects.requireNonNull(tenantId, "tenantId");
        if (service == null || !SERVICE.matcher(service).matches()) {
            throw new IllegalArgumentException("diagnostic service is invalid");
        }
        requireDigest(operatorSubjectDigest, "operator subject digest");
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                Map<String, Object> projection = readDiagnostic(connection, tenantId, service);
                auditDiagnostic(connection, tenantId, service, operatorSubjectDigest, projection);
                connection.commit();
                return projection;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new AdminActionException("ADMIN_ACTION_DATABASE_UNAVAILABLE",
                    "diagnostic store is unavailable", failure);
        }
    }

    public boolean ready() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                boolean ready = !privilegedRole(connection) && requiredTables(connection)
                        && forcedRls(connection);
                connection.rollback();
                return ready;
            } catch (SQLException | RuntimeException unavailable) {
                rollback(connection, unavailable);
                return false;
            }
        } catch (SQLException unavailable) {
            return false;
        }
    }

    private static AdminDomainCommand command(AdminActionEnvelope envelope, Instant createdAt) {
        AdminDomainCommand.Kind kind = AdminDomainCommand.Kind.valueOf(envelope.kind().name());
        AdminDomainCommand.OperationCode operation = AdminDomainCommand.OperationCode.valueOf(
                envelope.operationCode().name());
        AdminDomainCommand.ConsumerGroup group = switch (envelope.kind()) {
            case CASE_CLOSE, LIST_CHANGE -> AdminDomainCommand.ConsumerGroup.RISK;
            case REFUND_OVERRIDE -> AdminDomainCommand.ConsumerGroup.PAYMENT;
            case ROLLOUT_APPROVAL -> AdminDomainCommand.ConsumerGroup.ROLLOUT;
        };
        String digest = AdminDomainCommand.computeCommandDigest(envelope.approvalId(),
                envelope.tenantId(), envelope.projectId(), envelope.idempotencyKey(), kind,
                operation, group, envelope.targetId(), envelope.proposalDigest(),
                envelope.policyDigest(), envelope.approvalVersion(), envelope.proposerDigest(),
                envelope.approverDigest(), envelope.approvalExpiresAt(),
                envelope.fencingToken(), createdAt);
        return new AdminDomainCommand(envelope.approvalId(), envelope.tenantId(),
                envelope.projectId(), envelope.idempotencyKey(), digest, kind, operation, group,
                envelope.targetId(), envelope.proposalDigest(), envelope.policyDigest(),
                envelope.approvalVersion(), envelope.proposerDigest(),
                envelope.approverDigest(), envelope.approvalExpiresAt(),
                envelope.fencingToken(), createdAt);
    }

    private static DispatchClaim lockDispatch(Connection connection, String idempotencyKey)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT dispatch_id, project_id, approval_id, kind, operation_code, target_id,
                       proposal_digest, policy_digest, approval_version, proposer_digest,
                       approver_digest, state, lease_owner, lease_until, fencing_token,
                       approval_expires_at
                  FROM admin_action_dispatch
                 WHERE idempotency_key = ?
                 FOR UPDATE
                """)) {
            statement.setString(1, idempotencyKey);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw rejected("DISPATCH_NOT_FOUND", "admin dispatch is not staged");
                }
                return new DispatchClaim(result.getObject("dispatch_id", UUID.class),
                        result.getObject("project_id", UUID.class),
                        result.getObject("approval_id", UUID.class), result.getString("kind"),
                        result.getString("operation_code"), result.getString("target_id"),
                        result.getString("proposal_digest"), result.getString("policy_digest"),
                        result.getLong("approval_version"), result.getString("proposer_digest"),
                        result.getString("approver_digest"), result.getString("state"),
                        result.getString("lease_owner"), result.getTimestamp("lease_until"),
                        result.getLong("fencing_token"),
                        result.getTimestamp("approval_expires_at"));
            }
        }
    }

    private Optional<ExistingCommand> existingCommand(
            Connection connection, AdminActionEnvelope envelope) throws SQLException {
        Optional<AdminDomainCommandQueue.StoredCommand> found = queue.findCommand(connection,
                envelope.tenantId(), envelope.idempotencyKey());
        if (found.isEmpty()) {
            return Optional.empty();
        }
        AdminDomainCommand.ConsumerGroup expectedGroup = switch (envelope.kind()) {
            case CASE_CLOSE, LIST_CHANGE -> AdminDomainCommand.ConsumerGroup.RISK;
            case REFUND_OVERRIDE -> AdminDomainCommand.ConsumerGroup.PAYMENT;
            case ROLLOUT_APPROVAL -> AdminDomainCommand.ConsumerGroup.ROLLOUT;
        };
        AdminDomainCommand stored = found.orElseThrow().command();
        if (!envelope.approvalId().equals(stored.commandId())
                || !envelope.projectId().equals(stored.projectId())
                || !envelope.idempotencyKey().equals(stored.idempotencyKey())
                || !envelope.kind().name().equals(stored.kind().name())
                || !envelope.operationCode().name().equals(stored.operationCode().name())
                || expectedGroup != stored.consumerGroup()
                || !envelope.targetId().equals(stored.targetId())
                || !envelope.proposalDigest().equals(stored.proposalDigest())
                || !envelope.policyDigest().equals(stored.policyDigest())
                || envelope.approvalVersion() != stored.approvalVersion()
                || !envelope.proposerDigest().equals(stored.proposerDigest())
                || !envelope.approverDigest().equals(stored.approverDigest())
                || !envelope.approvalExpiresAt().equals(stored.approvalExpiresAt())) {
            throw rejected("IDEMPOTENCY_CONFLICT",
                    "admin command belongs to another immutable approval");
        }
        return Optional.of(new ExistingCommand(stored, found.orElseThrow().state()));
    }

    private static void requireLiveClaim(AdminActionEnvelope envelope, DispatchClaim claim,
            Instant now) {
        if (!envelope.dispatchId().equals(claim.dispatchId())
                || !envelope.projectId().equals(claim.projectId())
                || !envelope.approvalId().equals(claim.approvalId())
                || !envelope.kind().name().equals(claim.kind())
                || !envelope.operationCode().name().equals(claim.operationCode())
                || !envelope.targetId().equals(claim.targetId())
                || !envelope.proposalDigest().equals(claim.proposalDigest())
                || !envelope.policyDigest().equals(claim.policyDigest())
                || envelope.approvalVersion() != claim.approvalVersion()
                || !envelope.proposerDigest().equals(claim.proposerDigest())
                || !envelope.approverDigest().equals(claim.approverDigest())
                || !"DISPATCHING".equals(claim.state())
                || !envelope.workerId().equals(claim.leaseOwner())
                || envelope.fencingToken() != claim.fencingToken()
                || claim.leaseUntil() == null || claim.approvalExpiresAt() == null
                || !envelope.leaseUntil().equals(claim.leaseUntil().toInstant())
                || !envelope.approvalExpiresAt().equals(
                        claim.approvalExpiresAt().toInstant())) {
            throw rejected("STALE_DISPATCH_FENCE",
                    "admin dispatch lease or immutable binding is stale");
        }
        if (!now.isBefore(claim.leaseUntil().toInstant())
                || !now.isBefore(claim.approvalExpiresAt().toInstant())) {
            throw rejected("DISPATCH_LEASE_EXPIRED", "admin dispatch lease has expired");
        }
    }

    private static Approval lockApproval(Connection connection, UUID approvalId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT approval_id, project_id, kind, operation_code, target_id,
                       proposal_digest, policy_digest, permission, resource_type, proposer_id,
                       status, version, expires_at, decided_at, decided_by,
                       decision_reason_code, decision_ticket_digest
                  FROM admin_approval
                 WHERE approval_id = ?::uuid
                 FOR UPDATE
                """)) {
            statement.setString(1, approvalId.toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw rejected("APPROVAL_NOT_FOUND", "admin approval is unavailable");
                }
                return new Approval(result.getObject("approval_id", UUID.class),
                        result.getObject("project_id", UUID.class), result.getString("kind"),
                        result.getString("operation_code"), result.getString("target_id"),
                        result.getString("proposal_digest"), result.getString("policy_digest"),
                        result.getString("permission"), result.getString("resource_type"),
                        result.getString("proposer_id"), result.getString("status"),
                        result.getLong("version"), result.getTimestamp("expires_at"),
                        result.getTimestamp("decided_at"), result.getString("decided_by"),
                        result.getString("decision_reason_code"),
                        result.getString("decision_ticket_digest"));
            }
        }
    }

    private static void requireApproval(AdminActionEnvelope envelope, Approval approval,
            Instant now) {
        PolicyBinding expected = POLICY.get(envelope.kind());
        if (!envelope.approvalId().equals(approval.approvalId())
                || !envelope.projectId().equals(approval.projectId())
                || !envelope.kind().name().equals(approval.kind())
                || !envelope.operationCode().name().equals(approval.operationCode())
                || !envelope.targetId().equals(approval.targetId())
                || !envelope.proposalDigest().equals(approval.proposalDigest())
                || !envelope.policyDigest().equals(approval.policyDigest())
                || !expected.permission().equals(approval.permission())
                || !expected.resourceType().equals(approval.resourceType())
                || !"APPROVED".equals(approval.status())
                || approval.version() != envelope.approvalVersion()
                || approval.expiresAt() == null
                || !envelope.approvalExpiresAt().equals(approval.expiresAt().toInstant())
                || approval.decidedAt() == null || approval.decidedBy() == null
                || approval.decisionReasonCode() == null
                || approval.decisionTicketDigest() == null
                || !envelope.proposerDigest().equals(sha256(approval.proposerId()))
                || !envelope.approverDigest().equals(sha256(approval.decidedBy()))
                || approval.proposerId().equals(approval.decidedBy())) {
            throw rejected("APPROVAL_MISMATCH",
                    "admin approval does not match the immutable dispatch");
        }
        if (!now.isBefore(approval.expiresAt().toInstant())) {
            throw rejected("APPROVAL_EXPIRED", "admin approval has expired");
        }
    }

    private static void requireReplay(AdminDomainCommandQueue.EffectReceipt receipt,
            AdminActionEnvelope envelope, AdminDomainCommand command) {
        if (!receipt.tenantId().equals(envelope.tenantId())
                || !receipt.projectId().equals(envelope.projectId())
                || !receipt.approvalId().equals(envelope.approvalId())
                || !receipt.commandDigest().equals(command.commandDigest())
                || !receipt.kind().name().equals(envelope.kind().name())
                || !receipt.operationCode().name().equals(envelope.operationCode().name())
                || !receipt.targetId().equals(envelope.targetId())
                || !receipt.proposalDigest().equals(envelope.proposalDigest())
                || !receipt.policyDigest().equals(envelope.policyDigest())) {
            throw rejected("IDEMPOTENCY_CONFLICT",
                    "admin receipt belongs to another immutable command");
        }
    }

    private static AdminActionReceipt toReceipt(AdminDomainCommandQueue.EffectReceipt receipt) {
        return new AdminActionReceipt(receipt.receiptId(), receipt.idempotencyKey(),
                receipt.approvalId(), receipt.proposalDigest(), receipt.executedAt());
    }

    private static Map<String, Object> readDiagnostic(Connection connection, UUID tenantId,
            String service) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT safe_projection::text AS safe_projection
                  FROM admin_diagnostic_snapshot
                 WHERE tenant_id = ?::uuid AND service_name = ?
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, service);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw rejected("DIAGNOSTIC_NOT_FOUND",
                            "diagnostic projection is unavailable");
                }
                Map<String, Object> projection = Json.object(result.getString(1));
                if (!tenantId.toString().equals(projection.get("tenantId"))
                        || !service.equals(projection.get("service"))) {
                    throw rejected("DIAGNOSTIC_BINDING_INVALID",
                            "diagnostic projection is not tenant-bound");
                }
                return projection;
            }
        }
    }

    private static void auditDiagnostic(Connection connection, UUID tenantId, String service,
            String operatorDigest, Map<String, Object> projection) throws SQLException {
        UUID eventId = UUID.randomUUID();
        Instant occurredAt = databaseNow(connection);
        String projectionDigest = CanonicalPayload.sha256Hex(projection);
        String eventDigest = CanonicalPayload.sha256Hex(Map.of(
                "event_id", eventId.toString(), "tenant_id", tenantId.toString(),
                "operator_digest", operatorDigest, "service", service,
                "projection_digest", projectionDigest, "occurred_at", occurredAt.toString()));
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO admin_action_diagnostic_audit
                  (event_id, tenant_id, operator_digest, service_name, projection_digest,
                   event_digest, occurred_at)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, eventId.toString());
            statement.setString(2, tenantId.toString());
            statement.setString(3, operatorDigest);
            statement.setString(4, service);
            statement.setString(5, projectionDigest);
            statement.setString(6, eventDigest);
            statement.setTimestamp(7, Timestamp.from(occurredAt));
            statement.executeUpdate();
        }
    }

    private static boolean privilegedRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user
                """); ResultSet result = statement.executeQuery()) {
            return !result.next() || result.getBoolean(1) || result.getBoolean(2);
        }
    }

    private static boolean requiredTables(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT relname FROM pg_class
                 WHERE relnamespace = current_schema()::regnamespace AND relkind = 'r'
                """); ResultSet result = statement.executeQuery()) {
            java.util.HashSet<String> found = new java.util.HashSet<>();
            while (result.next()) {
                found.add(result.getString(1));
            }
            return found.containsAll(REQUIRED_TABLES);
        }
    }

    private static boolean forcedRls(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
                 WHERE relnamespace = current_schema()::regnamespace AND relname = ANY (?)
                """)) {
            statement.setArray(1, connection.createArrayOf("text", FORCE_RLS_TABLES.toArray()));
            try (ResultSet result = statement.executeQuery()) {
                java.util.HashSet<String> found = new java.util.HashSet<>();
                while (result.next()) {
                    if (!result.getBoolean(2) || !result.getBoolean(3)) {
                        return false;
                    }
                    found.add(result.getString(1));
                }
                return found.containsAll(FORCE_RLS_TABLES);
            }
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
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

    private static void requireDigest(String value, String label) {
        if (value == null || !DIGEST.matcher(value).matches()) {
            throw new IllegalArgumentException(label + " is invalid");
        }
    }

    private static String sha256(String value) {
        Objects.requireNonNull(value, "digest input");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK is missing SHA-256", impossible);
        }
    }

    private static AdminActionException rejected(String code, String message) {
        return new AdminActionException(code, message);
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private record PolicyBinding(String permission, String resourceType) { }

    private record DispatchClaim(UUID dispatchId, UUID projectId, UUID approvalId, String kind,
            String operationCode, String targetId, String proposalDigest, String policyDigest,
            long approvalVersion, String proposerDigest, String approverDigest, String state,
            String leaseOwner, Timestamp leaseUntil, long fencingToken,
            Timestamp approvalExpiresAt) { }

    private record Approval(UUID approvalId, UUID projectId, String kind, String operationCode,
            String targetId, String proposalDigest, String policyDigest, String permission,
            String resourceType, String proposerId, String status, long version,
            Timestamp expiresAt, Timestamp decidedAt, String decidedBy,
            String decisionReasonCode, String decisionTicketDigest) { }

    private record ExistingCommand(AdminDomainCommand command,
            AdminDomainCommandQueue.State state) { }
}
