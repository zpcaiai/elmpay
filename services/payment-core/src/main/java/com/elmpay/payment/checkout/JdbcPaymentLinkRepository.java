package com.elmpay.payment.checkout;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL B57 repository with atomic one-time redemption under FORCE RLS. */
public final class JdbcPaymentLinkRepository implements PaymentLinkRepository {
    private final DataSource dataSource;

    public JdbcPaymentLinkRepository(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Record createOrGet(Record candidate) {
        Objects.requireNonNull(candidate, "candidate");
        return transaction(candidate.tenantId(), connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO payment_link
                      (id,tenant_id,project_id,checkout_session_id,token_digest,
                       signing_key_version,idempotency_digest,request_digest,expires_at,
                       created_at,version)
                    VALUES (?,?,?,?,?,?,?,?,?,?,1)
                    ON CONFLICT (tenant_id,project_id,idempotency_digest) DO NOTHING
                    """)) {
                statement.setObject(1, candidate.id());
                statement.setObject(2, candidate.tenantId());
                statement.setObject(3, candidate.projectId());
                statement.setObject(4, candidate.checkoutSessionId());
                statement.setString(5, candidate.tokenDigest());
                statement.setString(6, candidate.signingKeyVersion());
                statement.setString(7, candidate.idempotencyDigest());
                statement.setString(8, candidate.requestDigest());
                statement.setTimestamp(9, Timestamp.from(candidate.expiresAt()));
                statement.setTimestamp(10, Timestamp.from(candidate.createdAt()));
                statement.executeUpdate();
            }
            Record stored = byIdempotency(connection, candidate.tenantId(), candidate.projectId(),
                    candidate.idempotencyDigest());
            if (!constantEquals(candidate.requestDigest(), stored.requestDigest())) {
                throw new IllegalStateException("payment-link idempotency conflict");
            }
            return stored;
        });
    }

    @Override
    public Record consume(UUID tenantId, String tokenDigest, Instant consumedAt) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(consumedAt, "consumedAt");
        return transaction(tenantId, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE payment_link
                       SET consumed_at=?,version=version+1
                     WHERE tenant_id=? AND token_digest=? AND consumed_at IS NULL
                       AND expires_at>?
                    RETURNING *
                    """)) {
                statement.setTimestamp(1, Timestamp.from(consumedAt));
                statement.setObject(2, tenantId);
                statement.setString(3, tokenDigest);
                statement.setTimestamp(4, Timestamp.from(consumedAt));
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new SecurityException(
                                "payment link is unknown, expired, or already consumed");
                    }
                    return record(result);
                }
            }
        });
    }

    private static Record byIdempotency(Connection connection, UUID tenantId, UUID projectId,
            String digest) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT * FROM payment_link
                 WHERE tenant_id=? AND project_id=? AND idempotency_digest=?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, projectId);
            statement.setString(3, digest);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("payment-link insert did not persist");
                }
                return record(result);
            }
        }
    }

    private static Record record(ResultSet result) throws SQLException {
        Timestamp consumed = result.getTimestamp("consumed_at");
        return new Record(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("checkout_session_id", UUID.class),
                result.getString("token_digest"), result.getString("signing_key_version"),
                result.getString("idempotency_digest"), result.getString("request_digest"),
                result.getTimestamp("expires_at").toInstant(),
                consumed == null ? null : consumed.toInstant(),
                result.getTimestamp("created_at").toInstant(), result.getLong("version"));
    }

    private <T> T transaction(UUID tenantId, SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement tenant = connection.prepareStatement(
                        "SELECT set_config('app.tenant_id', ?, true)")) {
                    tenant.setString(1, tenantId.toString());
                    tenant.execute();
                }
                T value = work.run(connection);
                connection.commit();
                return value;
            } catch (RuntimeException | SQLException failure) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new IllegalStateException("payment-link persistence failed", failure);
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("payment-link database unavailable", failure);
        }
    }

    private static boolean constantEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T run(Connection connection) throws SQLException;
    }
}
