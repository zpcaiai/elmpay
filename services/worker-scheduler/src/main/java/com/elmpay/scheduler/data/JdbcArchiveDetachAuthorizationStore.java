package com.elmpay.scheduler.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Objects;
import javax.sql.DataSource;

/** Persists one already verified destructive authorization without executing it. */
final class JdbcArchiveDetachAuthorizationStore {
    private final DataSource dataSource;

    JdbcArchiveDetachAuthorizationStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    void ingest(ArchiveReceiptVerifier.VerifiedDetachAuthorization authorization) {
        byte[] actorSignature = authorization.actorSignature();
        byte[] approverSignature = authorization.approverSignature();
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT public.elmpay_record_archive_detach_authorization(
                        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """)) {
                statement.setString(1, authorization.partitionName());
                statement.setObject(2, authorization.releaseId());
                statement.setString(3, authorization.actorId());
                statement.setString(4, authorization.approverId());
                statement.setString(5, authorization.reason());
                statement.setString(6, authorization.ticketId());
                statement.setString(7, authorization.policyDigest());
                statement.setString(8, authorization.canonicalAuthorizationDigest());
                statement.setString(9, authorization.partitionReleaseKeyId());
                statement.setString(10, authorization.actorKeyId());
                statement.setString(11, authorization.actorNonce());
                statement.setBytes(12, actorSignature);
                statement.setString(13, authorization.approverKeyId());
                statement.setString(14, authorization.approverNonce());
                statement.setBytes(15, approverSignature);
                statement.setObject(16, authorization.issuedAt());
                statement.setObject(17, authorization.expiresAt());
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next() || result.next()) {
                        throw new SQLException(
                                "detach authorization capability returned an invalid shape");
                    }
                }
                connection.commit();
            } catch (SQLException | RuntimeException failure) {
                try {
                    connection.rollback();
                } catch (SQLException rollback) {
                    failure.addSuppressed(rollback);
                }
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException(
                    "archive detach authorization transaction failed", failure);
        } finally {
            Arrays.fill(actorSignature, (byte) 0);
            Arrays.fill(approverSignature, (byte) 0);
        }
    }
}
