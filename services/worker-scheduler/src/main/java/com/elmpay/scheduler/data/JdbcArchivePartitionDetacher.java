package com.elmpay.scheduler.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

/** Executes one already verified authorization and reconciles an uncertain commit. */
final class JdbcArchivePartitionDetacher {
    private final DataSource dataSource;

    JdbcArchivePartitionDetacher(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    void detach(ArchiveDetachExecutionRequest authorization) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT public.elmpay_detach_archive_partition(
                        ?,?,?)
                    """)) {
                statement.setString(1, authorization.partitionName());
                statement.setObject(2, authorization.releaseId());
                statement.setString(3, authorization.canonicalAuthorizationDigest());
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next() || result.next()) {
                        throw new SQLException("detach capability returned an invalid result shape");
                    }
                }
                try {
                    connection.commit();
                } catch (SQLException uncertain) {
                    if (observe(authorization)) {
                        return;
                    }
                    throw new IllegalStateException(
                            "archive detach commit outcome is UNKNOWN", uncertain);
                }
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("archive detach transaction failed", failure);
        }
    }

    private boolean observe(ArchiveDetachExecutionRequest authorization) {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                    SELECT public.elmpay_observe_archive_partition_detach(?,?,?)
                    """)) {
            statement.setString(1, authorization.partitionName());
            statement.setObject(2, authorization.releaseId());
            statement.setString(3, authorization.canonicalAuthorizationDigest());
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1) && !result.next();
            }
        } catch (SQLException failure) {
            return false;
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollback) {
            original.addSuppressed(rollback);
        }
    }
}
