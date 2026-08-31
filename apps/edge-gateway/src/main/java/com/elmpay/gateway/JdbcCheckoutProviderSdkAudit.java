package com.elmpay.gateway;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL append-only provider SDK authorization audit. */
public final class JdbcCheckoutProviderSdkAudit implements CheckoutProviderSdkAudit {
    private static final String INSERT = """
            INSERT INTO checkout_provider_sdk_audit(
              audit_id, tenant_id, project_id, merchant_id, checkout_session_id,
              payment_intent_id, provider_account_id, method, provider, actor_type, actor_id,
              request_id, channel_digest, business_order_digest, checkout_snapshot_digest,
              configuration_digest, capability_version, policy_version, session_expires_at,
              created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """;
    private final DataSource dataSource;

    public JdbcCheckoutProviderSdkAudit(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public void append(Receipt receipt) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, receipt.tenantId());
                try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
                    int index = 0;
                    statement.setObject(++index, receipt.auditId());
                    statement.setObject(++index, receipt.tenantId());
                    statement.setObject(++index, receipt.projectId());
                    statement.setObject(++index, receipt.merchantId());
                    statement.setObject(++index, UUID.fromString(receipt.checkoutSessionId()));
                    statement.setObject(++index, receipt.paymentIntentId());
                    statement.setObject(++index, receipt.providerAccountId());
                    statement.setString(++index, receipt.method());
                    statement.setString(++index, receipt.provider());
                    statement.setString(++index, receipt.actorType());
                    statement.setString(++index, receipt.actorId());
                    statement.setString(++index, receipt.requestId());
                    statement.setString(++index, receipt.channelDigest());
                    statement.setString(++index, receipt.businessOrderDigest());
                    statement.setString(++index, receipt.checkoutSnapshotDigest());
                    statement.setString(++index, receipt.configurationDigest());
                    statement.setString(++index, receipt.capabilityVersion());
                    statement.setString(++index, receipt.policyVersion());
                    statement.setTimestamp(++index, Timestamp.from(receipt.sessionExpiresAt()));
                    statement.setTimestamp(++index, Timestamp.from(receipt.createdAt()));
                    statement.executeUpdate();
                }
                connection.commit();
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("provider SDK audit could not be persisted", failure);
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
}
