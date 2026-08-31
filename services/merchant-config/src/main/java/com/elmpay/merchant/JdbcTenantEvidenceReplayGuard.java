package com.elmpay.merchant;

import com.elmpay.tenant.AuthorityEvidenceReceipt;
import com.elmpay.tenant.TenantEvidenceVerifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Objects;
import javax.sql.DataSource;

/** Durable, tenant-RLS nonce guard for verified tenant authority receipts. */
public final class JdbcTenantEvidenceReplayGuard implements TenantEvidenceVerifier.ReplayGuard {
    static final String INSERT_NONCE_SQL = """
            INSERT INTO tenant_authority_evidence_nonce
              (tenant_id,key_id,nonce,evidence_type,authority,decision_reference,
               payload_digest,receipt_digest,issued_at,expires_at)
            VALUES (?::uuid,?,?,?,?,?,?,?,?::timestamptz,?::timestamptz)
            ON CONFLICT (key_id,nonce) DO NOTHING
            """;
    static final String SELECT_NONCE_SQL = """
            SELECT receipt_digest
              FROM tenant_authority_evidence_nonce
             WHERE tenant_id = ?::uuid AND key_id = ? AND nonce = ?
            """;
    private final DataSource dataSource;

    public JdbcTenantEvidenceReplayGuard(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public boolean accept(AuthorityEvidenceReceipt receipt, String receiptDigest,
            Instant acceptedAt) {
        Objects.requireNonNull(receipt, "receipt");
        Objects.requireNonNull(receiptDigest, "receiptDigest");
        Objects.requireNonNull(acceptedAt, "acceptedAt");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, receipt.tenantId().toString());
                try (PreparedStatement insert = connection.prepareStatement(INSERT_NONCE_SQL)) {
                    insert.setString(1, receipt.tenantId().toString());
                    insert.setString(2, receipt.keyId());
                    insert.setString(3, receipt.nonce());
                    insert.setString(4, receipt.evidenceType().name());
                    insert.setString(5, receipt.authority());
                    insert.setString(6, receipt.decisionReference());
                    insert.setString(7, receipt.payloadDigest());
                    insert.setString(8, receiptDigest);
                    insert.setString(9, receipt.issuedAt().toString());
                    insert.setString(10, receipt.expiresAt().toString());
                    insert.executeUpdate();
                }
                String stored;
                try (PreparedStatement query = connection.prepareStatement(SELECT_NONCE_SQL)) {
                    query.setString(1, receipt.tenantId().toString());
                    query.setString(2, receipt.keyId());
                    query.setString(3, receipt.nonce());
                    try (ResultSet result = query.executeQuery()) {
                        if (!result.next()) {
                            throw new SecurityException(
                                    "tenant evidence nonce conflicts across tenant boundaries");
                        }
                        stored = result.getString(1);
                    }
                }
                connection.commit();
                return MessageDigest.isEqual(stored.getBytes(StandardCharsets.US_ASCII),
                        receiptDigest.getBytes(StandardCharsets.US_ASCII));
            } catch (RuntimeException | SQLException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException unavailable) {
            throw new SecurityException("tenant evidence replay store is unavailable",
                    unavailable);
        }
    }

    private static void setTenant(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId);
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
