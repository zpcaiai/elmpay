package com.elmpay.gateway;

import com.elmpay.payment.checkout.CheckoutSessionRepository;
import java.net.URI;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL checkout store with transaction-local tenant RLS context. */
public final class JdbcCheckoutSessionRepository implements CheckoutSessionRepository {
    private static final String COLUMNS = """
            session_id, tenant_id, project_id, merchant_id, payment_intent_id,
            business_order_no, amount_minor, currency, return_route_id, return_uri,
            device_context_digest, expires_at, key_id, nonce, allowed_methods,
            create_idempotency_key, request_digest, created_at
            """;
    private final DataSource dataSource;

    public JdbcCheckoutSessionRepository(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<Record> find(UUID tenantId, String sessionId) {
        return read(tenantId, connection -> query(connection,
                "SELECT " + COLUMNS + " FROM checkout_session"
                        + " WHERE tenant_id = ? AND session_id = ?",
                statement -> {
                    statement.setObject(1, tenantId);
                    statement.setObject(2, UUID.fromString(sessionId));
                }));
    }

    @Override
    public Optional<Record> findByCreateKey(UUID tenantId, UUID projectId,
            String idempotencyKey) {
        return read(tenantId, connection -> findByCreateKey(connection, tenantId, projectId,
                idempotencyKey));
    }

    @Override
    public Record createOrGet(Record candidate) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, candidate.tenantId());
                int inserted;
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO checkout_session (
                            session_id, tenant_id, project_id, merchant_id, payment_intent_id,
                            business_order_no, amount_minor, currency, return_route_id, return_uri,
                            device_context_digest, expires_at, key_id, nonce, allowed_methods,
                            create_idempotency_key, request_digest, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::timestamptz, ?, ?, ?, ?, ?,
                                ?::timestamptz)
                        ON CONFLICT DO NOTHING
                        """)) {
                    bind(statement, connection, candidate);
                    inserted = statement.executeUpdate();
                }
                Record result = inserted == 1 ? candidate : findByCreateKey(connection,
                        candidate.tenantId(), candidate.projectId(),
                        candidate.createIdempotencyKey()).orElseThrow(() ->
                                new IllegalStateException(
                                        "checkout uniqueness conflict was not an idempotent replay"));
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("checkout repository write failed", failure);
        }
    }

    private Optional<Record> read(UUID tenantId, SqlQuery query) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                Optional<Record> result = query.run(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("checkout repository read failed", failure);
        }
    }

    private static Optional<Record> findByCreateKey(Connection connection, UUID tenantId,
            UUID projectId, String idempotencyKey) throws SQLException {
        return query(connection, "SELECT " + COLUMNS + " FROM checkout_session"
                        + " WHERE tenant_id = ? AND project_id = ?"
                        + " AND create_idempotency_key = ?",
                statement -> {
                    statement.setObject(1, tenantId);
                    statement.setObject(2, projectId);
                    statement.setString(3, idempotencyKey);
                });
    }

    private static Optional<Record> query(Connection connection, String sql, Binder binder)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            binder.bind(statement);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? Optional.of(map(result)) : Optional.empty();
            }
        }
    }

    private static Record map(ResultSet result) throws SQLException {
        String[] methods = (String[]) result.getArray("allowed_methods").getArray();
        return new Record(result.getObject("session_id", UUID.class).toString(),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("merchant_id", UUID.class),
                result.getObject("payment_intent_id", UUID.class),
                result.getString("business_order_no"), result.getLong("amount_minor"),
                result.getString("currency"), result.getString("return_route_id"),
                URI.create(result.getString("return_uri")),
                result.getString("device_context_digest"),
                result.getTimestamp("expires_at").toInstant(), result.getString("key_id"),
                result.getString("nonce"), Set.copyOf(Arrays.asList(methods)),
                result.getString("create_idempotency_key"), result.getString("request_digest"),
                result.getTimestamp("created_at").toInstant());
    }

    private static void bind(PreparedStatement statement, Connection connection, Record value)
            throws SQLException {
        statement.setObject(1, UUID.fromString(value.sessionId()));
        statement.setObject(2, value.tenantId());
        statement.setObject(3, value.projectId());
        statement.setObject(4, value.merchantId());
        statement.setObject(5, value.paymentIntentId());
        statement.setString(6, value.businessOrderNo());
        statement.setLong(7, value.amountMinor());
        statement.setString(8, value.currency());
        statement.setString(9, value.returnRouteId());
        statement.setString(10, value.returnUri().toASCIIString());
        statement.setString(11, value.deviceContextDigest());
        statement.setString(12, value.expiresAt().toString());
        statement.setString(13, value.keyId());
        statement.setString(14, value.nonce());
        statement.setArray(15, connection.createArrayOf("text",
                value.allowedMethods().toArray(String[]::new)));
        statement.setString(16, value.createIdempotencyKey());
        statement.setString(17, value.requestDigest());
        statement.setString(18, value.createdAt().toString());
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

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    @FunctionalInterface
    private interface SqlQuery {
        Optional<Record> run(Connection connection) throws SQLException;
    }
}
