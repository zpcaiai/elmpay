package com.elmpay.reconciliation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.util.UUID;

/** Transaction-local PostgreSQL RLS identity helpers. */
final class TenantSession {
    private TenantSession() {}

    static UUID tenant(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("tenantId must be a UUID", invalid);
        }
    }

    static void setLocal(Connection connection, UUID tenant) throws SQLException {
        if (connection.getAutoCommit()) {
            throw new SQLException("tenant RLS context requires an explicit transaction");
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenant.toString());
            statement.execute();
        }
    }

    static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    static void rollbackUniqueConflict(Connection connection, Savepoint savepoint,
                                       SQLException failure) throws SQLException {
        if (!"23505".equals(failure.getSQLState())) {
            throw failure;
        }
        connection.rollback(savepoint);
    }
}
