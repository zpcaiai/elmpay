package com.elmpay.gateway;

import com.elmpay.payment.checkout.CheckoutProviderSdkSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** Selects one currently healthy, production provider account for a signed checkout snapshot. */
public final class JdbcCheckoutProviderSdkSource implements CheckoutProviderSdkSource {
    private static final String SQL = """
            SELECT pa.id, pa.provider, pc.method, pc.version AS capability_version,
                   rr.version AS route_version, ph.source_version, ph.version AS health_version,
                   rr.priority
              FROM provider_account pa
              JOIN tenant t ON t.id=pa.tenant_id
              JOIN project p ON p.id=pa.project_id AND p.tenant_id=pa.tenant_id
              JOIN merchant m ON m.id=pa.merchant_id AND m.tenant_id=pa.tenant_id
              JOIN provider_capability pc
                ON pc.tenant_id=pa.tenant_id AND pc.provider_account_id=pa.id
              JOIN routing_rule rr
                ON rr.tenant_id=pa.tenant_id AND rr.project_id=pa.project_id
               AND rr.provider_account_id=pa.id
              JOIN provider_method_health ph
                ON ph.tenant_id=pa.tenant_id AND ph.project_id=pa.project_id
               AND ph.provider_account_id=pa.id AND ph.method=pc.method
             WHERE pa.tenant_id=? AND pa.project_id=? AND pa.merchant_id=?
               AND t.status='active' AND p.status='active' AND m.status='active'
               AND pa.status='active' AND pa.environment='production'
               AND pc.method=? AND ?=ANY(pc.currencies) AND ?=ANY(pc.regions)
               AND ?=ANY(pc.device_classes)
               AND rr.enabled AND ? BETWEEN rr.min_amount_minor AND rr.max_amount_minor
               AND ph.available AND ph.observed_at >= CAST(? AS timestamptz) - INTERVAL '90 seconds'
             ORDER BY rr.priority, pa.id
            """;

    private final DataSource dataSource;

    public JdbcCheckoutProviderSdkSource(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<Selection> select(Request request) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, request.tenantId());
                List<Candidate> candidates = query(connection, request);
                connection.commit();
                if (candidates.isEmpty()) {
                    return Optional.empty();
                }
                Candidate winner = candidates.getFirst();
                if (candidates.size() > 1 && candidates.get(1).priority() == winner.priority()) {
                    throw new IllegalStateException(
                            "provider SDK route is ambiguous at the highest priority");
                }
                return Optional.of(new Selection(winner.providerAccountId(), winner.provider(),
                        winner.method(), winner.capabilityDigest()));
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("provider SDK capability read model is unavailable",
                    failure);
        }
    }

    private static List<Candidate> query(Connection connection, Request request)
            throws SQLException {
        List<Candidate> result = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(SQL)) {
            statement.setObject(1, request.tenantId());
            statement.setObject(2, request.projectId());
            statement.setObject(3, request.merchantId());
            statement.setString(4, request.method());
            statement.setString(5, request.currency());
            statement.setString(6, request.region());
            statement.setString(7, request.deviceClass());
            statement.setLong(8, request.amountMinor());
            statement.setTimestamp(9, Timestamp.from(request.now()));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    String versions = String.join("\u001f", rows.getString("capability_version"),
                            rows.getString("route_version"), rows.getString("source_version"),
                            Long.toString(rows.getLong("health_version")));
                    result.add(new Candidate(rows.getObject("id", UUID.class),
                            rows.getString("provider"), rows.getString("method"),
                            rows.getInt("priority"), "sha256:" + sha256(versions)));
                }
            }
        }
        return result;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK is missing SHA-256", impossible);
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

    private record Candidate(UUID providerAccountId, String provider, String method, int priority,
            String capabilityDigest) {
    }
}
