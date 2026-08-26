package com.elmpay.idempotency;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL-backed tenant-scoped idempotency lease and durable result registry. */
public final class JdbcIdempotencyRegistry implements IdempotencyRegistry {
    private final DataSource dataSource;
    private final Clock clock;

    public JdbcIdempotencyRegistry(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public IdempotencyClaim claim(UUID tenantId, String operation, String key, String requestHash,
            Duration leaseDuration, Duration retention) {
        validate(tenantId, operation, key, requestHash, leaseDuration, retention);
        Instant now = clock.instant();
        String proposedOwner = UUID.randomUUID().toString();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenantContext(connection, tenantId);
                insertIfAbsent(connection, tenantId, operation, key, requestHash, proposedOwner,
                        now, leaseDuration, retention);
                IdempotencyClaim claim = lockAndClaim(connection, tenantId, operation, key,
                        requestHash, proposedOwner, now, leaseDuration);
                connection.commit();
                return claim;
            } catch (RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new IdempotencyException("IDEMPOTENCY_STORE_UNAVAILABLE",
                        "cannot claim idempotency key", exception);
            }
        } catch (SQLException exception) {
            throw new IdempotencyException("IDEMPOTENCY_STORE_UNAVAILABLE",
                    "cannot connect to idempotency store", exception);
        }
    }

    @Override
    public void complete(UUID tenantId, String operation, String key, String ownerToken,
            StoredResult result) {
        Objects.requireNonNull(result, "result");
        updateFinal(tenantId, operation, key, ownerToken, "COMPLETED", null, result);
    }

    @Override
    public void markUnknown(UUID tenantId, String operation, String key, String ownerToken,
            String reasonCode) {
        if (reasonCode == null || reasonCode.isBlank()) {
            throw new IllegalArgumentException("unknown outcome reason is required");
        }
        updateFinal(tenantId, operation, key, ownerToken, "UNKNOWN", reasonCode, null);
    }

    private void updateFinal(UUID tenantId, String operation, String key, String ownerToken,
            String state, String reason, StoredResult result) {
        RequestFingerprint.validateKey(key);
        if (ownerToken == null || ownerToken.isBlank()) {
            throw new IllegalArgumentException("owner token is required");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenantContext(connection, tenantId);
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE idempotency_record
                        SET state = ?, unknown_reason = ?, response_status = ?, response_content_type = ?,
                            response_body = ?, completed_at = ?
                        WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?
                          AND owner_token = ? AND state = 'IN_PROGRESS'
                        """)) {
                    statement.setString(1, state);
                    statement.setString(2, reason);
                    if (result == null) {
                        statement.setNull(3, java.sql.Types.INTEGER);
                        statement.setNull(4, java.sql.Types.VARCHAR);
                        statement.setNull(5, java.sql.Types.BINARY);
                    } else {
                        statement.setInt(3, result.statusCode());
                        statement.setString(4, result.contentType());
                        statement.setBytes(5, result.body());
                    }
                    statement.setTimestamp(6, Timestamp.from(clock.instant()));
                    statement.setObject(7, tenantId);
                    statement.setString(8, operation);
                    statement.setString(9, key);
                    statement.setString(10, ownerToken);
                    if (statement.executeUpdate() != 1) {
                        throw new IdempotencyException("IDEMPOTENCY_OWNERSHIP_LOST",
                                "claim is no longer owned or was already finalized");
                    }
                }
                connection.commit();
            } catch (RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new IdempotencyException("IDEMPOTENCY_STORE_UNAVAILABLE",
                        "cannot finalize idempotency record", exception);
            }
        } catch (SQLException exception) {
            throw new IdempotencyException("IDEMPOTENCY_STORE_UNAVAILABLE",
                    "cannot finalize idempotency record", exception);
        }
    }

    private static void insertIfAbsent(Connection connection, UUID tenantId, String operation,
            String key, String requestHash, String owner, Instant now, Duration lease,
            Duration retention) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO idempotency_record
                  (tenant_id, operation, idempotency_key, request_hash, state, owner_token,
                   lease_expires_at, created_at, expires_at)
                VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?, ?, ?, ?)
                ON CONFLICT (tenant_id, operation, idempotency_key) DO NOTHING
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, operation);
            statement.setString(3, key);
            statement.setString(4, requestHash);
            statement.setString(5, owner);
            statement.setTimestamp(6, Timestamp.from(now.plus(lease)));
            statement.setTimestamp(7, Timestamp.from(now));
            statement.setTimestamp(8, Timestamp.from(now.plus(retention)));
            statement.executeUpdate();
        }
    }

    private static IdempotencyClaim lockAndClaim(Connection connection, UUID tenantId,
            String operation, String key, String requestHash, String proposedOwner, Instant now,
            Duration lease) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("""
                SELECT request_hash, state, owner_token, lease_expires_at,
                       response_status, response_content_type, response_body
                FROM idempotency_record
                WHERE tenant_id = ? AND operation = ? AND idempotency_key = ? FOR UPDATE
                """)) {
            query.setObject(1, tenantId);
            query.setString(2, operation);
            query.setString(3, key);
            try (ResultSet result = query.executeQuery()) {
                if (!result.next()) {
                    throw new IdempotencyException("IDEMPOTENCY_STORE_INCONSISTENT",
                            "record disappeared during claim");
                }
                if (!requestHash.equals(result.getString("request_hash"))) {
                    throw new IdempotencyException("IDEMPOTENCY_PAYLOAD_CONFLICT",
                            "the key was already used with another request");
                }
                String state = result.getString("state");
                if ("COMPLETED".equals(state)) {
                    return new IdempotencyClaim(IdempotencyClaim.Status.REPLAY, null,
                            new StoredResult(result.getInt("response_status"),
                                    result.getString("response_content_type"),
                                    result.getBytes("response_body")));
                }
                if ("UNKNOWN".equals(state)) {
                    return new IdempotencyClaim(IdempotencyClaim.Status.UNKNOWN_OUTCOME, null, null);
                }
                Timestamp leaseExpiry = result.getTimestamp("lease_expires_at");
                String currentOwner = result.getString("owner_token");
                if (proposedOwner.equals(currentOwner)) {
                    return new IdempotencyClaim(IdempotencyClaim.Status.OWNED, proposedOwner, null);
                }
                if (leaseExpiry != null && leaseExpiry.toInstant().isAfter(now)) {
                    return new IdempotencyClaim(IdempotencyClaim.Status.BUSY, null, null);
                }
            }
        }
        try (PreparedStatement update = connection.prepareStatement("""
                UPDATE idempotency_record SET owner_token = ?, lease_expires_at = ?
                WHERE tenant_id = ? AND operation = ? AND idempotency_key = ?
                  AND state = 'IN_PROGRESS'
                """)) {
            update.setString(1, proposedOwner);
            update.setTimestamp(2, Timestamp.from(now.plus(lease)));
            update.setObject(3, tenantId);
            update.setString(4, operation);
            update.setString(5, key);
            if (update.executeUpdate() != 1) {
                throw new IdempotencyException("IDEMPOTENCY_STORE_INCONSISTENT",
                        "expired claim could not be recovered");
            }
        }
        return new IdempotencyClaim(IdempotencyClaim.Status.OWNED, proposedOwner, null);
    }

    private static void validate(UUID tenantId, String operation, String key, String requestHash,
            Duration lease, Duration retention) {
        Objects.requireNonNull(tenantId, "tenantId");
        RequestFingerprint.validateKey(key);
        if (operation == null || !operation.matches("[a-z][a-z0-9_.-]{2,63}")) {
            throw new IllegalArgumentException("invalid idempotency operation");
        }
        if (requestHash == null || !requestHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("request hash must be lowercase SHA-256");
        }
        if (lease == null || lease.isNegative() || lease.isZero()
                || retention == null || retention.compareTo(lease) <= 0) {
            throw new IllegalArgumentException("invalid idempotency lease or retention");
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
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
