package com.elmpay.audit;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import javax.sql.DataSource;

/** Executes a state mutation and its hash-chained audit fact in one JDBC transaction. */
public final class JdbcAuditedMutation {
    @FunctionalInterface
    public interface Mutation<T> {
        T execute(Connection connection) throws SQLException;
    }

    private final DataSource dataSource;
    private final JdbcAuditLog auditLog;

    public JdbcAuditedMutation(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.auditLog = new JdbcAuditLog(dataSource);
    }

    public <T> T execute(UUID tenantId, Mutation<T> mutation,
            Function<? super T, AuditEvent> auditEventFactory) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(mutation, "mutation");
        Objects.requireNonNull(auditEventFactory, "auditEventFactory");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                JdbcAuditLog.setTenantContext(connection, tenantId);
                T result = mutation.execute(connection);
                AuditEvent event = Objects.requireNonNull(auditEventFactory.apply(result),
                        "audit event");
                if (!tenantId.equals(event.tenantId())) {
                    throw new SecurityException("mutation and audit event tenant mismatch");
                }
                auditLog.append(connection, event);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof SQLException sqlException) {
                    throw new IllegalStateException("audited mutation failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("audited mutation failed", exception);
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
