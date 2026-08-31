package com.elmpay.scheduler;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.LocalDate;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** Durable oldest-first business-date cursor; completion advances exactly one day. */
public final class JdbcReconciliationScheduleStore
        implements TenantReconciliationScheduler.ScheduleStore {
    private final DataSource dataSource;

    public JdbcReconciliationScheduleStore(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        Objects.requireNonNull(clock, "clock");
    }

    @Override
    public LocalDate next(UUID tenantId, String provider, LocalDate latestEligible) {
        return transaction(tenantId, connection -> {
            if (!hasEligibleProductionAccount(connection, tenantId, provider)) {
                return null;
            }
            LocalDate current = cursor(connection, tenantId, provider);
            if (current != null) {
                return current.isAfter(latestEligible) ? null : current;
            }
            LocalDate initial = oldestImmutableSourceDate(connection, tenantId, provider,
                    latestEligible);
            if (initial == null) {
                return null;
            }
            try (PreparedStatement insert = connection.prepareStatement("""
                    INSERT INTO reconciliation_schedule_cursor
                      (tenant_id,provider,next_business_date,fencing_token,updated_at)
                    VALUES (?,?,?,0,clock_timestamp()) ON CONFLICT DO NOTHING
                    """)) {
                insert.setObject(1, tenantId);
                insert.setString(2, provider);
                insert.setObject(3, initial);
                insert.executeUpdate();
            }
            current = cursor(connection, tenantId, provider);
            if (current == null) {
                throw new SQLException("reconciliation schedule cursor is missing");
            }
            return current.isAfter(latestEligible) ? null : current;
        });
    }

    private static boolean hasEligibleProductionAccount(Connection connection, UUID tenantId,
            String provider) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                  FROM provider_account account
                 WHERE account.tenant_id=?
                   AND account.provider=?
                   AND account.environment='production'
                   AND account.status='active'
                   AND EXISTS (
                       SELECT 1 FROM provider_capability capability
                        WHERE capability.tenant_id=account.tenant_id
                          AND capability.provider_account_id=account.id)
                 LIMIT 1
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, provider);
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static LocalDate oldestImmutableSourceDate(Connection connection, UUID tenantId,
            String provider, LocalDate latestEligible) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT min(candidate.business_date)
                  FROM (
                    SELECT (event.occurred_at AT TIME ZONE 'UTC')::date AS business_date
                      FROM outbox_event event
                     WHERE event.tenant_id=? AND event.event_type IN
                           ('payment_intent.captured','refund.succeeded')
                       AND event.payload->>'provider'=?
                    UNION ALL
                    SELECT (statement_entry.occurred_at AT TIME ZONE 'UTC')::date
                           AS business_date
                      FROM statement_file file
                      JOIN statement_row statement_entry
                        ON statement_entry.tenant_id=file.tenant_id
                       AND statement_entry.file_id=file.id
                     WHERE file.tenant_id=? AND file.reconciliation_provider=?
                  ) candidate
                 WHERE candidate.business_date<=?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, provider);
            statement.setObject(3, tenantId);
            statement.setString(4, provider);
            statement.setObject(5, latestEligible);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("oldest reconciliation source query returned no row");
                }
                LocalDate value = result.getObject(1, LocalDate.class);
                if (result.next()) {
                    throw new SQLException("oldest reconciliation source query is not scalar");
                }
                return value;
            }
        }
    }

    private static LocalDate cursor(Connection connection, UUID tenantId, String provider)
            throws SQLException {
        try (PreparedStatement select = connection.prepareStatement("""
                SELECT next_business_date FROM reconciliation_schedule_cursor
                 WHERE tenant_id=? AND provider=? FOR UPDATE
                """)) {
            select.setObject(1, tenantId);
            select.setString(2, provider);
            try (ResultSet result = select.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                LocalDate value = result.getObject(1, LocalDate.class);
                if (result.next()) {
                    throw new SQLException("reconciliation schedule cursor is not unique");
                }
                return value;
            }
        }
    }

    @Override
    public void completed(UUID tenantId, String provider, LocalDate businessDate) {
        transaction(tenantId, connection -> {
            LocalDate current;
            try (PreparedStatement select = connection.prepareStatement("""
                    SELECT next_business_date FROM reconciliation_schedule_cursor
                     WHERE tenant_id=? AND provider=? FOR UPDATE
                    """)) {
                select.setObject(1, tenantId);
                select.setString(2, provider);
                try (ResultSet result = select.executeQuery()) {
                    if (!result.next()) {
                        throw new SQLException("reconciliation schedule cursor is missing");
                    }
                    current = result.getObject(1, LocalDate.class);
                }
            }
            if (current.isAfter(businessDate)) {
                if (current.equals(businessDate.plusDays(1))) {
                    return null; // another replica already advanced this exact completed day
                }
                throw new IllegalStateException(
                        "reconciliation cursor rejected a stale completion");
            }
            if (!current.equals(businessDate)) {
                throw new IllegalStateException("reconciliation cursor cannot skip a business day");
            }
            try (PreparedStatement update = connection.prepareStatement("""
                    UPDATE reconciliation_schedule_cursor
                       SET next_business_date=?,fencing_token=fencing_token+1,
                           last_failure_code=NULL,last_failure_digest=NULL,
                           last_failure_at=NULL,updated_at=clock_timestamp()
                     WHERE tenant_id=? AND provider=? AND next_business_date=?
                    """)) {
                update.setObject(1, businessDate.plusDays(1));
                update.setObject(2, tenantId);
                update.setString(3, provider);
                update.setObject(4, businessDate);
                if (update.executeUpdate() != 1) {
                    throw new SQLException("reconciliation cursor advance lost its fence");
                }
            }
            return null;
        });
    }

    @Override
    public void failed(UUID tenantId, String provider, LocalDate businessDate,
            String failureCode, String failureDigest) {
        if (failureCode == null || !failureCode.matches("[A-Z][A-Z0-9_]{2,63}")
                || failureDigest == null || !failureDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("reconciliation failure binding is invalid");
        }
        transaction(tenantId, connection -> {
            LocalDate current = cursor(connection, tenantId, provider);
            if (current == null) {
                throw new SQLException("reconciliation schedule cursor is missing");
            }
            if (current.equals(businessDate.plusDays(1))) {
                return null; // completion won before a caller observed its commit
            }
            if (!current.equals(businessDate)) {
                throw new IllegalStateException(
                        "reconciliation failure cannot move or skip the cursor");
            }
            try (PreparedStatement update = connection.prepareStatement("""
                    UPDATE reconciliation_schedule_cursor
                       SET failure_count=failure_count+1,last_failure_code=?,
                           last_failure_digest=?,last_failure_at=clock_timestamp(),
                           fencing_token=fencing_token+1,updated_at=clock_timestamp()
                     WHERE tenant_id=? AND provider=? AND next_business_date=?
                    """)) {
                update.setString(1, failureCode);
                update.setString(2, failureDigest);
                update.setObject(3, tenantId);
                update.setString(4, provider);
                update.setObject(5, businessDate);
                if (update.executeUpdate() != 1) {
                    throw new SQLException("reconciliation failure record lost its fence");
                }
            }
            return null;
        });
    }

    private <T> T transaction(UUID tenantId, SqlWork<T> work) {
        Objects.requireNonNull(tenantId, "tenantId");
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
                throw new IllegalStateException("reconciliation schedule database failure",
                        failure);
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("reconciliation schedule database is unavailable",
                    failure);
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T run(Connection connection) throws SQLException;
    }
}
