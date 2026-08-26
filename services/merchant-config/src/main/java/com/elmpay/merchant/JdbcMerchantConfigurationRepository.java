package com.elmpay.merchant;

import com.elmpay.security.SecretReference;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
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
        return inTenantTransaction(tenantId, "cannot read provider account", connection -> {
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
    public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
        String sql = """
                SELECT pa.id, pa.tenant_id, pa.project_id, pa.merchant_id, pa.provider,
                       pa.environment, pa.provider_merchant_id, pa.credential_ref,
                       pa.credential_version, pa.status, pc.method, pc.currencies,
                       pc.regions, pc.authorization_capture, pc.partial_capture,
                       pc.partial_refund, pc.subscriptions, rr.priority, rr.version
                  FROM provider_account pa
                  JOIN provider_capability pc
                    ON pc.tenant_id = pa.tenant_id AND pc.provider_account_id = pa.id
                  JOIN routing_rule rr
                    ON rr.tenant_id = pa.tenant_id AND rr.project_id = pa.project_id
                   AND rr.provider_account_id = pa.id
                 WHERE pa.tenant_id = ?::uuid AND pa.project_id = ?::uuid
                   AND pa.merchant_id = ?::uuid AND pa.status = 'active'
                   AND pc.method = ? AND ? = ANY(pc.currencies) AND ? = ANY(pc.regions)
                   AND rr.enabled AND ? BETWEEN rr.min_amount_minor AND rr.max_amount_minor
                """;
        return inTenantTransaction(request.tenantId(), "cannot resolve provider routes",
                connection -> {
                    List<ProviderRoute> routes = new ArrayList<>();
                    try (PreparedStatement statement = connection.prepareStatement(sql)) {
                        statement.setString(1, request.tenantId().toString());
                        statement.setString(2, request.projectId().toString());
                        statement.setString(3, request.merchantId().toString());
                        statement.setString(4, request.method());
                        statement.setString(5, request.currency());
                        statement.setString(6, request.region());
                        statement.setLong(7, request.amountMinor());
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

    private <T> T inTenantTransaction(UUID tenantId, String failureMessage,
            SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
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
