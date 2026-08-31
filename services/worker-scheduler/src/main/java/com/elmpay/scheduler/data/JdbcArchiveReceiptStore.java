package com.elmpay.scheduler.data;

import java.util.Arrays;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

/** Persists only already verified receipts through the verifier-role capability functions. */
final class JdbcArchiveReceiptStore {
    private final DataSource dataSource;

    JdbcArchiveReceiptStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    void ingest(ArchiveReceiptVerifier.VerifiedBundle bundle) {
        Objects.requireNonNull(bundle, "bundle");
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try {
                requireVerifierRole(connection);
                for (ArchiveReceiptVerifier.VerifiedTenantReceipt receipt
                        : bundle.tenantReceipts()) {
                    recordTenant(connection, receipt);
                }
                recordRelease(connection, bundle.release());
                connection.commit();
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("verified archive receipt transaction failed", failure);
        }
    }

    private static void recordTenant(Connection connection,
            ArchiveReceiptVerifier.VerifiedTenantReceipt receipt) throws SQLException {
        byte[] signature = receipt.signature();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT public.elmpay_record_archive_tenant_receipt(
                    ?,?,?,?,?,?,?,?,?,?,?)
                """)) {
            statement.setObject(1, receipt.tenantId());
            statement.setString(2, receipt.partitionName());
            statement.setString(3, receipt.objectUri());
            statement.setString(4, receipt.manifestDigest());
            statement.setString(5, receipt.objectDigest());
            statement.setString(6, receipt.canonicalReceiptDigest());
            statement.setString(7, receipt.keyId());
            statement.setString(8, receipt.nonce());
            statement.setBytes(9, signature);
            statement.setObject(10, receipt.issuedAt());
            statement.setObject(11, receipt.expiresAt());
            requireOne(statement);
        } finally {
            Arrays.fill(signature, (byte) 0);
        }
    }

    private static void recordRelease(Connection connection,
            ArchiveReceiptVerifier.VerifiedPartitionRelease release) throws SQLException {
        byte[] signature = release.signature();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT public.elmpay_record_archive_partition_release(
                    ?,?,?,?,?,?,?,?,?,?,?,?,?)
                """)) {
            statement.setObject(1, release.releaseId());
            statement.setString(2, release.partitionName());
            statement.setInt(3, release.tenantCount());
            statement.setString(4, release.receiptSetBinding());
            statement.setString(5, release.receiptSetDigest());
            statement.setString(6, release.aggregateManifestBinding());
            statement.setString(7, release.aggregateManifestDigest());
            statement.setString(8, release.canonicalReceiptDigest());
            statement.setString(9, release.keyId());
            statement.setString(10, release.nonce());
            statement.setBytes(11, signature);
            statement.setObject(12, release.issuedAt());
            statement.setObject(13, release.expiresAt());
            requireOne(statement);
        } finally {
            Arrays.fill(signature, (byte) 0);
        }
    }

    private static void requireOne(PreparedStatement statement) throws SQLException {
        try (ResultSet result = statement.executeQuery()) {
            if (!result.next() || result.next()) {
                throw new SQLException("archive capability returned an invalid result shape");
            }
        }
    }

    private static void requireVerifierRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user = 'elmpay_archive_verifier'
                   AND session_user = current_user
                   AND NOT EXISTS (
                     SELECT 1 FROM pg_auth_members membership
                      JOIN pg_roles role ON role.oid = membership.member
                     WHERE role.rolname = current_user)
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.next()) {
                throw new IllegalStateException("archive verifier database role is not exact");
            }
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
