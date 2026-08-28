package com.elmpay.merchant;

import com.elmpay.security.SecretReference;
import com.elmpay.security.CanonicalPayload;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.sql.DataSource;

/** PostgreSQL configuration read model. Every query binds the tenant and project. */
public final class JdbcMerchantConfigurationRepository implements MerchantConfigurationRepository {
    private final DataSource dataSource;

    public JdbcMerchantConfigurationRepository(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId, UUID accountId) {
        String sql = """
                SELECT id, tenant_id, project_id, merchant_id, provider, environment,
                       provider_merchant_id, credential_ref, credential_version, status
                  FROM provider_account
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND id = ?::uuid
                """;
        return inTenantTransaction(tenantId, true, "cannot read provider account", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, accountId.toString());
                try (ResultSet result = statement.executeQuery()) {
                    return result.next() ? Optional.of(account(result)) : Optional.empty();
                }
            }
        });
    }

    @Override
    public Optional<ProviderAccount> findAccount(UUID tenantId, UUID accountId) {
        String sql = """
                SELECT id, tenant_id, project_id, merchant_id, provider, environment,
                       provider_merchant_id, credential_ref, credential_version, status
                  FROM provider_account
                 WHERE tenant_id = ?::uuid AND id = ?::uuid
                """;
        return inTenantTransaction(tenantId, true, "cannot read webhook provider account", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, accountId.toString());
                try (ResultSet result = statement.executeQuery()) {
                    return result.next() ? Optional.of(account(result)) : Optional.empty();
                }
            }
        });
    }

    @Override
    public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
        String sql = """
                WITH selected_policy AS (
                    SELECT CASE
                             WHEN candidate_version IS NOT NULL AND ? < canary_basis_points
                               THEN candidate_version
                             ELSE stable_version
                           END AS version
                      FROM routing_policy_assignment
                     WHERE tenant_id = ?::uuid AND project_id = ?::uuid
                )
                SELECT pa.id, pa.tenant_id, pa.project_id, pa.merchant_id, pa.provider,
                       pa.environment, pa.provider_merchant_id, pa.credential_ref,
                       pa.credential_version, pa.status, pc.method, pc.currencies,
                       pc.regions, pc.authorization_capture, pc.partial_capture,
                       pc.partial_refund, pc.subscriptions, rr.priority, rr.version
                  FROM provider_account pa
                  JOIN provider_capability pc
                    ON pc.tenant_id = pa.tenant_id AND pc.provider_account_id = pa.id
                  JOIN routing_policy_rule rr
                    ON rr.tenant_id = pa.tenant_id AND rr.project_id = pa.project_id
                   AND rr.provider_account_id = pa.id
                  JOIN selected_policy selected ON selected.version = rr.version
                 WHERE pa.tenant_id = ?::uuid AND pa.project_id = ?::uuid
                   AND pa.merchant_id = ?::uuid AND pa.status = 'active'
                   AND pc.method = ? AND ? = ANY(pc.currencies) AND ? = ANY(pc.regions)
                   AND rr.enabled AND ? BETWEEN rr.min_amount_minor AND rr.max_amount_minor
                """;
        return inTenantTransaction(request.tenantId(), true, "cannot resolve provider routes",
                connection -> {
                    List<ProviderRoute> routes = new ArrayList<>();
                    try (PreparedStatement statement = connection.prepareStatement(sql)) {
                        statement.setInt(1, stableCanaryBucket(request.stableSplitKey()));
                        statement.setString(2, request.tenantId().toString());
                        statement.setString(3, request.projectId().toString());
                        statement.setString(4, request.tenantId().toString());
                        statement.setString(5, request.projectId().toString());
                        statement.setString(6, request.merchantId().toString());
                        statement.setString(7, request.method());
                        statement.setString(8, request.currency());
                        statement.setString(9, request.region());
                        statement.setLong(10, request.amountMinor());
                        try (ResultSet result = statement.executeQuery()) {
                            while (result.next()) {
                                ProviderAccount account = account(result);
                                ProviderCapability capability = new ProviderCapability(
                                        account.provider(), result.getString("method"),
                                        strings(result, "currencies"), strings(result, "regions"),
                                        result.getBoolean("authorization_capture"),
                                        result.getBoolean("partial_capture"),
                                        result.getBoolean("partial_refund"),
                                        result.getBoolean("subscriptions"));
                                routes.add(new ProviderRoute(account, capability,
                                        result.getInt("priority"), result.getString("version")));
                            }
                        }
                    }
                    return List.copyOf(routes);
                });
    }

    @Override
    public void recordRoutingDecision(RoutingRequest request, ProviderRoute selected,
            List<ProviderRoute> evaluatedRoutes) {
        java.util.Objects.requireNonNull(request, "request");
        java.util.Objects.requireNonNull(selected, "selected");
        List<ProviderRoute> safeRoutes = List.copyOf(evaluatedRoutes);
        if (safeRoutes.isEmpty() || safeRoutes.stream().noneMatch(selected::equals)
                || safeRoutes.stream().anyMatch(route ->
                        !request.tenantId().equals(route.account().tenantId())
                                || !request.projectId().equals(route.account().projectId())
                                || !request.merchantId().equals(route.account().merchantId()))) {
            throw new SecurityException("routing decision scope or evaluated routes are invalid");
        }
        List<Map<String, Object>> evaluated = safeRoutes.stream()
                .sorted(java.util.Comparator.comparing(route -> route.account().id()))
                .map(JdbcMerchantConfigurationRepository::canonicalRoute)
                .toList();
        String requestDigest = CanonicalPayload.sha256Hex(Map.of(
                "tenant", request.tenantId(), "project", request.projectId(),
                "merchant", request.merchantId(), "method", request.method(),
                "currency", request.currency(), "region", request.region(),
                "amount_minor", request.amountMinor(), "split_key", request.stableSplitKey()));
        String evaluatedDigest = CanonicalPayload.sha256Hex(evaluated);
        String splitKeyDigest = CanonicalPayload.sha256Hex(request.stableSplitKey());
        String sql = """
                INSERT INTO routing_decision
                  (decision_id, tenant_id, project_id, split_key_digest, request_digest,
                   evaluated_routes_digest, selected_version, provider_account_id, decided_at)
                VALUES (gen_random_uuid(), ?::uuid, ?::uuid, ?, ?, ?, ?, ?::uuid, now())
                ON CONFLICT (tenant_id, project_id, split_key_digest) DO NOTHING
                RETURNING decision_id
                """;
        inTenantTransaction(request.tenantId(), false, "cannot persist routing decision",
                connection -> {
                    try (PreparedStatement statement = connection.prepareStatement(sql)) {
                        statement.setString(1, request.tenantId().toString());
                        statement.setString(2, request.projectId().toString());
                        statement.setString(3, splitKeyDigest);
                        statement.setString(4, requestDigest);
                        statement.setString(5, evaluatedDigest);
                        statement.setString(6, selected.ruleVersion());
                        statement.setString(7, selected.account().id().toString());
                        try (ResultSet result = statement.executeQuery()) {
                            if (result.next()) {
                                return null;
                            }
                        }
                    }
                    requireMatchingDecision(connection, request, splitKeyDigest, requestDigest,
                            evaluatedDigest, selected);
                    return null;
                });
    }

    private static Map<String, Object> canonicalRoute(ProviderRoute route) {
        ProviderCapability capability = route.capability();
        return Map.ofEntries(
                Map.entry("provider_account_id", route.account().id()),
                Map.entry("provider", route.account().provider()),
                Map.entry("account_status", route.account().status()),
                Map.entry("priority", route.priority()),
                Map.entry("rule_version", route.ruleVersion()),
                Map.entry("method", capability.method()),
                Map.entry("currencies", capability.currencies().stream().sorted().toList()),
                Map.entry("regions", capability.regions().stream().sorted().toList()),
                Map.entry("authorization_capture", capability.authorizationCapture()),
                Map.entry("partial_capture", capability.partialCapture()),
                Map.entry("partial_refund", capability.partialRefund()),
                Map.entry("subscriptions", capability.subscriptions()));
    }

    private static void requireMatchingDecision(Connection connection, RoutingRequest request,
            String splitKeyDigest, String requestDigest, String evaluatedDigest,
            ProviderRoute selected) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT request_digest, evaluated_routes_digest, selected_version,
                       provider_account_id
                  FROM routing_decision
                 WHERE tenant_id=?::uuid AND project_id=?::uuid AND split_key_digest=?
                """)) {
            statement.setString(1, request.tenantId().toString());
            statement.setString(2, request.projectId().toString());
            statement.setString(3, splitKeyDigest);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !requestDigest.equals(result.getString(1))
                        || !evaluatedDigest.equals(result.getString(2))
                        || !selected.ruleVersion().equals(result.getString(3))
                        || !selected.account().id().equals(result.getObject(4, UUID.class))) {
                    throw new RoutingException("ROUTING_DECISION_CONFLICT",
                            "stable split key was already bound to another route");
                }
            }
        }
    }

    static int stableCanaryBucket(String stableSplitKey) {
        String digest = CanonicalPayload.sha256Hex(stableSplitKey);
        return (int) (Long.parseLong(digest.substring(0, 8), 16) % 10_000L);
    }

    private static ProviderAccount account(ResultSet result) throws SQLException {
        return new ProviderAccount(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("merchant_id", UUID.class), result.getString("provider"),
                result.getString("environment"), result.getString("provider_merchant_id"),
                SecretReference.parse(result.getString("credential_ref")),
                result.getString("credential_version"),
                AccountStatus.valueOf(result.getString("status").toUpperCase(java.util.Locale.ROOT)));
    }

    private static Set<String> strings(ResultSet result, String column) throws SQLException {
        String[] values = (String[]) result.getArray(column).getArray();
        return Arrays.stream(values).collect(Collectors.toUnmodifiableSet());
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private <T> T inTenantTransaction(UUID tenantId, boolean readOnly, String failureMessage,
            SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(readOnly);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                T result = work.execute(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof SQLException sqlException) {
                    throw sqlException;
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException(failureMessage, exception);
        }
    }

    private static void rollback(Connection connection, Throwable failure) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            failure.addSuppressed(rollbackFailure);
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T execute(Connection connection) throws SQLException;
    }
}
