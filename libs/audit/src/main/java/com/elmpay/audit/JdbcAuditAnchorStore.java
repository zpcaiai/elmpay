package com.elmpay.audit;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** Durable audit-root anchor queue with crash leases and fencing-token acknowledgements. */
public final class JdbcAuditAnchorStore implements AuditAnchorWorker.Store {
    private final DataSource dataSource;

    public JdbcAuditAnchorStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<AuditAnchorWorker.Candidate> claim(UUID tenantId, String workerId,
            Instant now, Instant leaseUntil) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(workerId, "workerId");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(leaseUntil, "leaseUntil");
        if (!leaseUntil.isAfter(now)) {
            throw new IllegalArgumentException("leaseUntil must be after now");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                JdbcAuditLog.setTenantContext(connection, tenantId);
                try (PreparedStatement lock = connection.prepareStatement(
                        "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")) {
                    lock.setString(1, "audit-anchor:" + tenantId);
                    lock.execute();
                }
                materializeLatestRoot(connection, tenantId, now);
                AuditAnchorWorker.Candidate candidate = leaseNext(connection, tenantId,
                        workerId, now, leaseUntil);
                connection.commit();
                return Optional.ofNullable(candidate);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot claim audit anchor", exception);
        }
    }

    @Override
    public void recordVerifiedReceipt(AuditAnchorWorker.Candidate candidate,
            AuditAnchorWorker.Receipt receipt, Instant receivedAt) {
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(receipt, "receipt");
        Objects.requireNonNull(receivedAt, "receivedAt");
        if (!candidate.tenantId().equals(receipt.tenantId())
                || candidate.throughSequence() != receipt.throughSequence()
                || !candidate.chainHash().equals(receipt.chainHash())) {
            throw new SecurityException("verified receipt does not match the leased audit root");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                JdbcAuditLog.setTenantContext(connection, candidate.tenantId());
                try (PreparedStatement request = connection.prepareStatement("""
                        UPDATE audit_anchor_request
                           SET state='ANCHORED', anchored_at=?, lease_until=NULL,
                               updated_at=?, last_error_code=NULL
                         WHERE tenant_id=?::uuid AND anchor_id=?::uuid AND state='LEASED'
                           AND worker_id=? AND fencing_token=?
                           AND through_sequence=? AND chain_hash=?
                        """)) {
                    request.setTimestamp(1, Timestamp.from(receipt.anchoredAt()));
                    request.setTimestamp(2, Timestamp.from(receivedAt));
                    request.setString(3, candidate.tenantId().toString());
                    request.setString(4, candidate.anchorId().toString());
                    request.setString(5, candidate.workerId());
                    request.setLong(6, candidate.fencingToken());
                    request.setLong(7, candidate.throughSequence());
                    request.setString(8, candidate.chainHash());
                    if (request.executeUpdate() != 1) {
                        throw new SQLException("audit anchor acknowledgement lost its lease");
                    }
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO audit_anchor_receipt
                          (tenant_id, anchor_id, authority_id, external_receipt_id,
                           through_sequence, chain_hash, anchored_at, signature, received_at)
                        VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?)
                        """)) {
                    statement.setString(1, candidate.tenantId().toString());
                    statement.setString(2, candidate.anchorId().toString());
                    statement.setString(3, receipt.authorityId());
                    statement.setString(4, receipt.receiptId());
                    statement.setLong(5, candidate.throughSequence());
                    statement.setString(6, candidate.chainHash());
                    statement.setTimestamp(7, Timestamp.from(receipt.anchoredAt()));
                    statement.setBytes(8, receipt.signature());
                    statement.setTimestamp(9, Timestamp.from(receivedAt));
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("audit anchor receipt was not persisted");
                    }
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot persist verified audit anchor", exception);
        }
    }

    @Override
    public void recordFailure(AuditAnchorWorker.Candidate candidate, String errorCode,
            Instant retryAt) {
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(errorCode, "errorCode");
        Objects.requireNonNull(retryAt, "retryAt");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                JdbcAuditLog.setTenantContext(connection, candidate.tenantId());
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE audit_anchor_request
                           SET state='PENDING', attempts=attempts+1, next_attempt_at=?,
                               lease_until=NULL, last_error_code=?, updated_at=now()
                         WHERE tenant_id=?::uuid AND anchor_id=?::uuid AND state='LEASED'
                           AND worker_id=? AND fencing_token=?
                        """)) {
                    statement.setTimestamp(1, Timestamp.from(retryAt));
                    statement.setString(2, errorCode);
                    statement.setString(3, candidate.tenantId().toString());
                    statement.setString(4, candidate.anchorId().toString());
                    statement.setString(5, candidate.workerId());
                    statement.setLong(6, candidate.fencingToken());
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("audit anchor failure update lost its lease");
                    }
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot reschedule audit anchor", exception);
        }
    }

    private static void materializeLatestRoot(Connection connection, UUID tenantId, Instant now)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO audit_anchor_request
                  (anchor_id, tenant_id, through_sequence, chain_hash, state, attempts,
                   fencing_token, next_attempt_at, created_at, updated_at)
                SELECT gen_random_uuid(), tenant_id, sequence_no, chain_hash, 'PENDING', 0, 0,
                       ?, ?, ?
                  FROM audit_event
                 WHERE tenant_id=?::uuid
                   AND NOT EXISTS (
                       SELECT 1 FROM audit_anchor_request request
                        WHERE request.tenant_id=audit_event.tenant_id
                          AND request.through_sequence=audit_event.sequence_no)
                 ORDER BY sequence_no DESC
                 LIMIT 1
                ON CONFLICT (tenant_id, through_sequence) DO NOTHING
                """)) {
            statement.setTimestamp(1, Timestamp.from(now));
            statement.setTimestamp(2, Timestamp.from(now));
            statement.setTimestamp(3, Timestamp.from(now));
            statement.setString(4, tenantId.toString());
            statement.executeUpdate();
        }
    }

    private static AuditAnchorWorker.Candidate leaseNext(Connection connection, UUID tenantId,
            String workerId, Instant now, Instant leaseUntil) throws SQLException {
        UUID anchorId;
        long throughSequence;
        String chainHash;
        long fencingToken;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT anchor_id, through_sequence, chain_hash, fencing_token
                  FROM audit_anchor_request
                 WHERE tenant_id=?::uuid AND state IN ('PENDING','LEASED')
                   AND next_attempt_at<=?
                   AND (state='PENDING' OR lease_until<=?)
                 ORDER BY through_sequence
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setTimestamp(2, Timestamp.from(now));
            statement.setTimestamp(3, Timestamp.from(now));
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                anchorId = result.getObject(1, UUID.class);
                throughSequence = result.getLong(2);
                chainHash = result.getString(3);
                fencingToken = result.getLong(4) + 1;
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE audit_anchor_request
                   SET state='LEASED', worker_id=?, lease_until=?, fencing_token=?, updated_at=?
                 WHERE tenant_id=?::uuid AND anchor_id=?::uuid
                """)) {
            statement.setString(1, workerId);
            statement.setTimestamp(2, Timestamp.from(leaseUntil));
            statement.setLong(3, fencingToken);
            statement.setTimestamp(4, Timestamp.from(now));
            statement.setString(5, tenantId.toString());
            statement.setString(6, anchorId.toString());
            if (statement.executeUpdate() != 1) {
                throw new SQLException("audit anchor lease update failed");
            }
        }
        return new AuditAnchorWorker.Candidate(anchorId, tenantId, throughSequence, chainHash,
                fencingToken, workerId);
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
