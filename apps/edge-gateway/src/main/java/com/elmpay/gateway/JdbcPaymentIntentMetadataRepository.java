package com.elmpay.gateway;

import com.elmpay.security.CanonicalPayload;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL metadata binding with tenant RLS and immutable replay comparison. */
public final class JdbcPaymentIntentMetadataRepository
        implements PaymentIntentMetadataRepository {
    private final DataSource dataSource;

    public JdbcPaymentIntentMetadataRepository(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public void bind(UUID tenantId, UUID projectId, UUID paymentIntentId, String idempotencyKey,
            Map<String, String> metadata) {
        Map<String, String> immutable = Map.copyOf(new TreeMap<>(metadata));
        String digest = digest(projectId, idempotencyKey, immutable);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO payment_intent_metadata
                          (tenant_id, project_id, payment_intent_id, create_idempotency_key,
                           request_digest, metadata)
                        VALUES (?, ?, ?, ?, ?, ?::jsonb)
                        ON CONFLICT (tenant_id, payment_intent_id) DO NOTHING
                        """)) {
                    statement.setObject(1, tenantId);
                    statement.setObject(2, projectId);
                    statement.setObject(3, paymentIntentId);
                    statement.setString(4, idempotencyKey);
                    statement.setString(5, digest);
                    statement.setString(6, Json.stringify(immutable));
                    statement.executeUpdate();
                }
                String stored = digest(connection, tenantId, paymentIntentId);
                if (!digest.equals(stored)) {
                    throw InMemoryPaymentIntentMetadataRepository.conflict();
                }
                connection.commit();
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("payment intent metadata write failed", failure);
        }
    }

    @Override
    public Map<String, String> find(UUID tenantId, UUID paymentIntentId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                Map<String, String> found = Map.of();
                try (PreparedStatement statement = connection.prepareStatement("""
                        SELECT metadata::text FROM payment_intent_metadata
                        WHERE tenant_id = ? AND payment_intent_id = ?
                        """)) {
                    statement.setObject(1, tenantId);
                    statement.setObject(2, paymentIntentId);
                    try (ResultSet result = statement.executeQuery()) {
                        if (result.next()) {
                            found = stringMap(Json.object(result.getString(1)));
                        }
                    }
                }
                connection.commit();
                return found;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("payment intent metadata read failed", failure);
        }
    }

    private static String digest(Connection connection, UUID tenantId, UUID paymentIntentId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT request_digest FROM payment_intent_metadata
                WHERE tenant_id = ? AND payment_intent_id = ? FOR UPDATE
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, paymentIntentId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getString(1) : null;
            }
        }
    }

    private static String digest(UUID projectId, String idempotencyKey,
            Map<String, String> metadata) {
        return CanonicalPayload.sha256Hex(Map.of("project_id", projectId,
                "idempotency_key", idempotencyKey, "metadata", metadata));
    }

    private static Map<String, String> stringMap(Map<String, Object> raw) {
        Map<String, String> result = new LinkedHashMap<>();
        raw.forEach((key, value) -> {
            if (!(value instanceof String text)) {
                throw new IllegalStateException("stored payment metadata is not string-valued");
            }
            result.put(key, text);
        });
        return Map.copyOf(result);
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
