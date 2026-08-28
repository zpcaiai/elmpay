package com.elmpay.merchant;

import com.elmpay.security.CanonicalPayload;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** Immutable version control, two-person activation, stable canary and audited rollback. */
public final class JdbcRoutingPolicyControl {
    private static final int MAX_CANARY_BASIS_POINTS = 2_500;

    public record Rule(UUID providerAccountId, int priority, long minimumAmountMinor,
            long maximumAmountMinor, boolean enabled) {
        public Rule {
            Objects.requireNonNull(providerAccountId, "providerAccountId");
            if (priority < 0 || minimumAmountMinor < 0
                    || maximumAmountMinor < minimumAmountMinor) {
                throw new IllegalArgumentException("routing rule bounds are invalid");
            }
        }

        Map<String, Object> canonical() {
            return Map.of("provider_account_id", providerAccountId, "priority", priority,
                    "minimum_amount_minor", minimumAmountMinor,
                    "maximum_amount_minor", maximumAmountMinor, "enabled", enabled);
        }
    }

    public record Simulation(String selectedVersion, UUID providerAccountId,
            String evaluatedRoutesDigest, boolean movesMoney) {
        public Simulation {
            requireVersion(selectedVersion);
            Objects.requireNonNull(providerAccountId, "providerAccountId");
            requireSha256(evaluatedRoutesDigest, "evaluatedRoutesDigest");
            if (movesMoney) {
                throw new IllegalArgumentException("routing simulation must never move money");
            }
        }
    }

    private final DataSource dataSource;

    public JdbcRoutingPolicyControl(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public String proposeVersion(UUID tenantId, UUID projectId, String version,
            List<Rule> rules, String actorId, String reason, String ticketId, Instant now) {
        requireScope(tenantId, projectId);
        requireVersion(version);
        requireActor(actorId, "actorId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        Objects.requireNonNull(now, "now");
        List<Rule> normalized = List.copyOf(rules).stream()
                .sorted(Comparator.comparing((Rule rule) -> rule.providerAccountId().toString())
                        .thenComparingInt(Rule::priority)
                        .thenComparingLong(Rule::minimumAmountMinor))
                .toList();
        if (normalized.isEmpty() || normalized.size() > 500
                || normalized.stream().map(Rule::providerAccountId).distinct().count()
                        != normalized.size()) {
            throw new IllegalArgumentException("routing version requires unique provider rules");
        }
        String digest = CanonicalPayload.sha256Hex(Map.of("tenant", tenantId,
                "project", projectId, "version", version,
                "rules", normalized.stream().map(Rule::canonical).toList()));
        inTransaction(tenantId, "cannot propose routing version", connection -> {
            int inserted;
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO routing_policy_version
                      (tenant_id, project_id, version, content_digest, created_by,
                       reason, ticket_id, created_at)
                    VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, project_id, version) DO NOTHING
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, version);
                statement.setString(4, digest);
                statement.setString(5, actorId);
                statement.setString(6, reason);
                statement.setString(7, ticketId);
                statement.setTimestamp(8, Timestamp.from(now));
                inserted = statement.executeUpdate();
            }
            if (inserted == 0) {
                requireExistingDigest(connection, tenantId, projectId, version, digest);
                return null;
            }
            for (Rule rule : normalized) {
                insertRule(connection, tenantId, projectId, version, rule);
            }
            insertChange(connection, tenantId, projectId, "PROPOSE", version, null, 0,
                    null, null, 0, actorId, reason, ticketId, now);
            return null;
        });
        return digest;
    }

    public void approveVersion(UUID tenantId, UUID projectId, String version,
            String expectedDigest, String approverId, String reason, String ticketId, Instant now) {
        requireScope(tenantId, projectId);
        requireVersion(version);
        requireSha256(expectedDigest, "expectedDigest");
        requireActor(approverId, "approverId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        Objects.requireNonNull(now, "now");
        inTransaction(tenantId, "cannot approve routing version", connection -> {
            String creator;
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT content_digest, created_by FROM routing_policy_version
                     WHERE tenant_id=?::uuid AND project_id=?::uuid AND version=?
                     FOR SHARE
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, version);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next() || !expectedDigest.equals(result.getString(1))) {
                        throw new SecurityException("routing approval digest does not match");
                    }
                    creator = result.getString(2);
                }
            }
            if (approverId.equals(creator)) {
                throw new SecurityException("routing creator cannot approve the same version");
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO routing_policy_approval
                      (tenant_id, project_id, version, content_digest, approver_id,
                       reason, ticket_id, approved_at)
                    VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, project_id, version, approver_id) DO NOTHING
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, version);
                statement.setString(4, expectedDigest);
                statement.setString(5, approverId);
                statement.setString(6, reason);
                statement.setString(7, ticketId);
                statement.setTimestamp(8, Timestamp.from(now));
                if (statement.executeUpdate() == 1) {
                    insertChange(connection, tenantId, projectId, "APPROVE", version, null, 0,
                            null, null, 0, approverId, reason, ticketId, now);
                }
            }
            return null;
        });
    }

    public void activate(UUID tenantId, UUID projectId, String stableVersion,
            String candidateVersion, int canaryBasisPoints, String actorId,
            String reason, String ticketId, Instant now) {
        requireScope(tenantId, projectId);
        requireVersion(stableVersion);
        if (candidateVersion == null) {
            if (canaryBasisPoints != 0) {
                throw new IllegalArgumentException("stable-only activation requires zero canary");
            }
        } else {
            requireVersion(candidateVersion);
            if (stableVersion.equals(candidateVersion) || canaryBasisPoints < 1
                    || canaryBasisPoints > MAX_CANARY_BASIS_POINTS) {
                throw new IllegalArgumentException("canary activation is invalid");
            }
        }
        requireActor(actorId, "actorId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        Objects.requireNonNull(now, "now");
        inTransaction(tenantId, "cannot activate routing policy", connection -> {
            requireTwoApprovals(connection, tenantId, projectId, stableVersion);
            if (candidateVersion != null) {
                requireTwoApprovals(connection, tenantId, projectId, candidateVersion);
            }
            Assignment before = assignment(connection, tenantId, projectId);
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO routing_policy_assignment
                      (tenant_id, project_id, stable_version, candidate_version,
                       canary_basis_points, previous_stable_version,
                       previous_candidate_version, previous_canary_basis_points,
                       revision, updated_by, reason, ticket_id, updated_at)
                    VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, project_id) DO UPDATE
                       SET previous_stable_version=routing_policy_assignment.stable_version,
                           previous_candidate_version=routing_policy_assignment.candidate_version,
                           previous_canary_basis_points=routing_policy_assignment.canary_basis_points,
                           stable_version=EXCLUDED.stable_version,
                           candidate_version=EXCLUDED.candidate_version,
                           canary_basis_points=EXCLUDED.canary_basis_points,
                           revision=routing_policy_assignment.revision+1,
                           updated_by=EXCLUDED.updated_by, reason=EXCLUDED.reason,
                           ticket_id=EXCLUDED.ticket_id, updated_at=EXCLUDED.updated_at
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, stableVersion);
                statement.setString(4, candidateVersion);
                statement.setInt(5, canaryBasisPoints);
                statement.setString(6, before == null ? null : before.stableVersion());
                statement.setString(7, before == null ? null : before.candidateVersion());
                statement.setInt(8, before == null ? 0 : before.canaryBasisPoints());
                statement.setString(9, actorId);
                statement.setString(10, reason);
                statement.setString(11, ticketId);
                statement.setTimestamp(12, Timestamp.from(now));
                statement.executeUpdate();
            }
            insertChange(connection, tenantId, projectId, "ACTIVATE", stableVersion,
                    candidateVersion, canaryBasisPoints,
                    before == null ? null : before.stableVersion(),
                    before == null ? null : before.candidateVersion(),
                    before == null ? 0 : before.canaryBasisPoints(),
                    actorId, reason, ticketId, now);
            return null;
        });
    }

    /** Emergency rollback deliberately needs no approval, but is reason/ticket bound and audited. */
    public void rollback(UUID tenantId, UUID projectId, String actorId,
            String reason, String ticketId, Instant now) {
        requireScope(tenantId, projectId);
        requireActor(actorId, "actorId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        Objects.requireNonNull(now, "now");
        inTransaction(tenantId, "cannot roll back routing policy", connection -> {
            Assignment current = assignment(connection, tenantId, projectId);
            if (current == null || current.previousStableVersion() == null) {
                throw new IllegalStateException("no previously activated routing version exists");
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE routing_policy_assignment
                       SET stable_version=previous_stable_version,
                           candidate_version=previous_candidate_version,
                           canary_basis_points=previous_canary_basis_points,
                           previous_stable_version=?, previous_candidate_version=?,
                           previous_canary_basis_points=?, revision=revision+1,
                           updated_by=?, reason=?, ticket_id=?, updated_at=?
                     WHERE tenant_id=?::uuid AND project_id=?::uuid
                    """)) {
                statement.setString(1, current.stableVersion());
                statement.setString(2, current.candidateVersion());
                statement.setInt(3, current.canaryBasisPoints());
                statement.setString(4, actorId);
                statement.setString(5, reason);
                statement.setString(6, ticketId);
                statement.setTimestamp(7, Timestamp.from(now));
                statement.setString(8, tenantId.toString());
                statement.setString(9, projectId.toString());
                if (statement.executeUpdate() != 1) {
                    throw new SQLException("routing rollback lost the assignment lock");
                }
            }
            insertChange(connection, tenantId, projectId, "ROLLBACK",
                    current.previousStableVersion(), current.previousCandidateVersion(),
                    current.previousCanaryBasisPoints(), current.stableVersion(),
                    current.candidateVersion(), current.canaryBasisPoints(),
                    actorId, reason, ticketId, now);
            return null;
        });
    }

    public Simulation simulate(RoutingRequest request) {
        List<ProviderRoute> routes = new JdbcMerchantConfigurationRepository(dataSource)
                .eligibleRoutes(request).stream()
                .filter(route -> route.account().status().permitsNewPayments())
                .filter(route -> route.capability().supports(
                        request.method(), request.currency(), request.region()))
                .sorted(Comparator.comparingInt(ProviderRoute::priority)
                        .thenComparing(route -> route.account().provider())
                        .thenComparing(route -> route.account().id()))
                .toList();
        if (routes.isEmpty()) {
            throw new RoutingException("NO_ELIGIBLE_PROVIDER",
                    "routing simulation found no eligible provider");
        }
        ProviderRoute selected = routes.getFirst();
        String evaluated = CanonicalPayload.sha256Hex(routes.stream()
                .map(route -> route.account().id().toString()).sorted().toList());
        return new Simulation(selected.ruleVersion(), selected.account().id(), evaluated, false);
    }

    private record Assignment(String stableVersion, String candidateVersion, int canaryBasisPoints,
            String previousStableVersion, String previousCandidateVersion,
            int previousCanaryBasisPoints) {}

    private static Assignment assignment(Connection connection, UUID tenantId, UUID projectId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT stable_version, candidate_version, canary_basis_points,
                       previous_stable_version, previous_candidate_version,
                       previous_canary_basis_points
                  FROM routing_policy_assignment
                 WHERE tenant_id=?::uuid AND project_id=?::uuid
                 FOR UPDATE
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? new Assignment(result.getString(1), result.getString(2),
                        result.getInt(3), result.getString(4), result.getString(5),
                        result.getInt(6)) : null;
            }
        }
    }

    private static void requireTwoApprovals(Connection connection, UUID tenantId,
            UUID projectId, String version) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(DISTINCT approval.approver_id)
                  FROM routing_policy_version version
                  JOIN routing_policy_approval approval
                    ON approval.tenant_id=version.tenant_id
                   AND approval.project_id=version.project_id
                   AND approval.version=version.version
                   AND approval.content_digest=version.content_digest
                 WHERE version.tenant_id=?::uuid AND version.project_id=?::uuid
                   AND version.version=?
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, version);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || result.getLong(1) < 2) {
                    throw new SecurityException(
                            "routing activation requires two distinct digest-bound approvals");
                }
            }
        }
    }

    private static void requireExistingDigest(Connection connection, UUID tenantId,
            UUID projectId, String version, String digest) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT content_digest FROM routing_policy_version
                 WHERE tenant_id=?::uuid AND project_id=?::uuid AND version=?
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, version);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !digest.equals(result.getString(1))) {
                    throw new RoutingException("ROUTING_VERSION_CONFLICT",
                            "routing version is already bound to another digest");
                }
            }
        }
    }

    private static void insertRule(Connection connection, UUID tenantId, UUID projectId,
            String version, Rule rule) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO routing_policy_rule
                  (tenant_id, project_id, version, provider_account_id, priority,
                   min_amount_minor, max_amount_minor, enabled)
                VALUES (?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?, ?)
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, version);
            statement.setString(4, rule.providerAccountId().toString());
            statement.setInt(5, rule.priority());
            statement.setLong(6, rule.minimumAmountMinor());
            statement.setLong(7, rule.maximumAmountMinor());
            statement.setBoolean(8, rule.enabled());
            statement.executeUpdate();
        }
    }

    private static void insertChange(Connection connection, UUID tenantId, UUID projectId,
            String action, String stableVersion, String candidateVersion, int canaryBasisPoints,
            String previousStableVersion, String previousCandidateVersion,
            int previousCanaryBasisPoints, String actorId, String reason,
            String ticketId, Instant now) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO routing_policy_change
                  (change_id, tenant_id, project_id, action, stable_version, candidate_version,
                   canary_basis_points, previous_stable_version, previous_candidate_version,
                   previous_canary_basis_points, actor_id, reason, ticket_id, occurred_at)
                VALUES (gen_random_uuid(), ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, action);
            statement.setString(4, stableVersion);
            statement.setString(5, candidateVersion);
            statement.setInt(6, canaryBasisPoints);
            statement.setString(7, previousStableVersion);
            statement.setString(8, previousCandidateVersion);
            statement.setInt(9, previousCanaryBasisPoints);
            statement.setString(10, actorId);
            statement.setString(11, reason);
            statement.setString(12, ticketId);
            statement.setTimestamp(13, Timestamp.from(now));
            statement.executeUpdate();
        }
    }

    private <T> T inTransaction(UUID tenantId, String failureMessage, SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                T result = work.execute(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof SQLException sqlException) {
                    throw new IllegalStateException(failureMessage, sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException(failureMessage, exception);
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static void requireScope(UUID tenantId, UUID projectId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
    }

    private static void requireVersion(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._-]{1,80}")) {
            throw new IllegalArgumentException("routing version has an invalid format");
        }
    }

    private static void requireSha256(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static void requireActor(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9._@:-]{3,160}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 160
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T execute(Connection connection) throws SQLException;
    }
}
