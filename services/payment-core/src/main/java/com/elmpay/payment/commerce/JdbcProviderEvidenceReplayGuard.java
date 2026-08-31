package com.elmpay.payment.commerce;

import com.elmpay.provider.ProviderEvidenceReceipt;
import com.elmpay.provider.ProviderEvidenceVerifier;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL nonce guard with exact-idempotent replay and tenant RLS context. */
public final class JdbcProviderEvidenceReplayGuard
        implements ProviderEvidenceVerifier.ReplayGuard {
    private final DataSource dataSource;

    public JdbcProviderEvidenceReplayGuard(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public boolean accept(ProviderEvidenceReceipt receipt, String receiptDigest,
            Instant acceptedAt) {
        Objects.requireNonNull(receipt, "receipt");
        Map<String, String> fields = receipt.fields();
        UUID tenantId = UUID.fromString(required(fields, "tenantId"));
        UUID projectId = UUID.fromString(required(fields, "projectId"));
        String entityId = required(fields, "entityId");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement tenant = connection.prepareStatement(
                        "SELECT set_config('app.tenant_id', ?, true)")) {
                    tenant.setString(1, tenantId.toString());
                    tenant.execute();
                }
                try (PreparedStatement insert = connection.prepareStatement("""
                        INSERT INTO provider_evidence_nonce
                          (tenant_id,project_id,key_id,nonce,evidence_type,entity_id,
                           receipt_digest,accepted_at)
                        VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (key_id,nonce) DO NOTHING
                        """)) {
                    insert.setObject(1, tenantId);
                    insert.setObject(2, projectId);
                    insert.setString(3, receipt.keyId());
                    insert.setString(4, receipt.nonce());
                    insert.setString(5, receipt.evidenceType());
                    insert.setString(6, entityId);
                    insert.setString(7, receiptDigest);
                    insert.setTimestamp(8, Timestamp.from(acceptedAt));
                    insert.executeUpdate();
                }
                String stored;
                try (PreparedStatement query = connection.prepareStatement("""
                        SELECT receipt_digest FROM provider_evidence_nonce
                         WHERE tenant_id=? AND key_id=? AND nonce=?
                        """)) {
                    query.setObject(1, tenantId);
                    query.setString(2, receipt.keyId());
                    query.setString(3, receipt.nonce());
                    try (ResultSet result = query.executeQuery()) {
                        if (!result.next()) {
                            throw new SecurityException("provider evidence nonce was not stored");
                        }
                        stored = result.getString(1);
                    }
                }
                connection.commit();
                return MessageDigestSupport.constantTimeEquals(stored, receiptDigest);
            } catch (RuntimeException | SQLException failure) {
                connection.rollback();
                throw failure;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException failure) {
            throw new SecurityException("provider evidence replay store is unavailable", failure);
        }
    }

    private static String required(Map<String, String> fields, String name) {
        String value = fields.get(name);
        if (value == null || value.isBlank()) {
            throw new SecurityException("provider evidence " + name + " is required");
        }
        return value;
    }

    private static final class MessageDigestSupport {
        private MessageDigestSupport() {
        }

        private static boolean constantTimeEquals(String left, String right) {
            return java.security.MessageDigest.isEqual(
                    left.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    right.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
    }
}
