package com.elmpay.audit;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** Transactional append-only audit log with a per-tenant hash chain. */
public final class JdbcAuditLog {
    private final DataSource dataSource;

    public JdbcAuditLog(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public String append(AuditEvent event) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenantContext(connection, event.tenantId());
                try (PreparedStatement lock = connection.prepareStatement(
                        "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")) {
                    lock.setString(1, event.tenantId().toString());
                    lock.execute();
                }
                String previous = lastHash(connection, event.tenantId().toString());
                String chainHash = com.elmpay.security.CanonicalPayload.sha256Hex(
                        java.util.Map.of("previous", previous, "event", event.canonicalDigest()));
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO audit_event
                          (id, tenant_id, actor_id, action, target_type, target_id, reason, ticket_id,
                           before_digest, after_digest, correlation_id, occurred_at,
                           previous_hash, chain_hash)
                        VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::timestamptz, ?, ?)
                        """)) {
                    statement.setString(1, event.id().toString());
                    statement.setString(2, event.tenantId().toString());
                    statement.setString(3, event.actorId());
                    statement.setString(4, event.action());
                    statement.setString(5, event.targetType());
                    statement.setString(6, event.targetId());
                    statement.setString(7, event.reason());
                    statement.setString(8, event.ticketId());
                    statement.setString(9, com.elmpay.security.CanonicalPayload.sha256Hex(event.before()));
                    statement.setString(10, com.elmpay.security.CanonicalPayload.sha256Hex(event.after()));
                    statement.setString(11, event.correlationId());
                    statement.setString(12, event.occurredAt().toString());
                    statement.setString(13, previous);
                    statement.setString(14, chainHash);
                    statement.executeUpdate();
                }
                connection.commit();
                return chainHash;
            } catch (RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new IllegalStateException("cannot append audit event", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot append audit event", exception);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static String lastHash(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT chain_hash FROM audit_event
                WHERE tenant_id = ?::uuid ORDER BY sequence_no DESC LIMIT 1 FOR UPDATE
                """)) {
            statement.setString(1, tenantId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getString(1) : "GENESIS";
            }
        }
    }

    /** Set a transaction-local RLS identity; callers must already be in a transaction. */
    static void setTenantContext(Connection connection, UUID tenantId) throws SQLException {
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(tenantId, "tenantId");
        if (connection.getAutoCommit()) {
            throw new SQLException("tenant RLS context requires an explicit transaction");
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }
}
