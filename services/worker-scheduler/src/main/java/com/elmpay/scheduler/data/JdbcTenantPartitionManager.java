package com.elmpay.scheduler.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** Creates bounded monthly partitions and fail-closes detach without external archive evidence. */
public final class JdbcTenantPartitionManager {
    private static final DateTimeFormatter SUFFIX = DateTimeFormatter.ofPattern("yyyyMM");
    private static final int MAX_CREATE_MONTHS = 24;
    private final DataSource dataSource;
    private final Clock clock;

    public JdbcTenantPartitionManager(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public int ensureMonthlyPartitions(YearMonth firstMonth, int count, String actorId,
            String reason, String ticketId) {
        Objects.requireNonNull(firstMonth, "firstMonth");
        requireText(actorId, "actorId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        if (count < 1 || count > MAX_CREATE_MONTHS) {
            throw new IllegalArgumentException("partition count must be 1..24");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                advisoryLock(connection);
                int created = 0;
                for (int offset = 0; offset < count; offset++) {
                    YearMonth month = firstMonth.plusMonths(offset);
                    if (createPartition(connection, month)) {
                        audit(connection, partitionName(month), "CREATE", actorId, null,
                                reason, ticketId, clock.instant());
                        created++;
                    }
                }
                connection.commit();
                return created;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot maintain tenant archive partitions", exception);
        }
    }

    public void detachArchivedPartition(UUID tenantId, YearMonth month, String actorId,
            String approverId, String reason, String ticketId) {
        Objects.requireNonNull(tenantId, "tenantId");
        requireText(actorId, "actorId");
        requireText(approverId, "approverId");
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
        if (actorId.equals(approverId)) {
            throw new IllegalArgumentException("partition detach requires a distinct approver");
        }
        if (!month.atEndOfMonth().atTime(23, 59, 59).toInstant(ZoneOffset.UTC)
                .isBefore(clock.instant())) {
            throw new IllegalArgumentException("an active or future partition cannot be detached");
        }
        String partition = partitionName(month);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                advisoryLock(connection);
                setTenant(connection, tenantId);
                requireVerifiedReceipt(connection, tenantId, partition);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("ALTER TABLE tenant_archive_fact DETACH PARTITION " + partition);
                    statement.execute("ALTER TABLE " + partition + " SET SCHEMA elmpay_archive_detached");
                }
                audit(connection, partition, "DETACH", actorId, approverId, reason, ticketId,
                        clock.instant());
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot detach tenant archive partition", exception);
        }
    }

    private static boolean createPartition(Connection connection, YearMonth month) throws SQLException {
        String partition = partitionName(month);
        boolean existed;
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT to_regclass(?) IS NOT NULL")) {
            statement.setString(1, partition);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("partition catalog query returned no row");
                }
                existed = result.getBoolean(1);
            }
        }
        if (existed) {
            return false;
        }
        String lower = month.atDay(1).toString();
        String upper = month.plusMonths(1).atDay(1).toString();
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE " + partition +
                    " PARTITION OF tenant_archive_fact FOR VALUES FROM ('" + lower +
                    "') TO ('" + upper + "')");
        }
        return true;
    }

    private static String partitionName(YearMonth month) {
        return "tenant_archive_fact_" + SUFFIX.format(month);
    }

    private static void advisoryLock(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("SELECT pg_advisory_xact_lock(hashtextextended(" +
                    "'elmpay:tenant_archive_partition', 0))");
            statement.execute("CREATE SCHEMA IF NOT EXISTS elmpay_archive_detached");
        }
    }

    private static void requireVerifiedReceipt(Connection connection, UUID tenantId,
            String partition) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT manifest_digest,object_digest,external_verifier_id,external_receipt_id " +
                        "FROM tenant_archive_export_receipt WHERE tenant_id=?::uuid " +
                        "AND partition_name=? FOR UPDATE")) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, partition);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getString(1).matches("[0-9a-f]{64}")
                        || !result.getString(2).matches("[0-9a-f]{64}")
                        || result.getString(3).isBlank() || result.getString(4).isBlank()) {
                    throw new IllegalStateException(
                            "partition detach requires a verified external archive receipt");
                }
            }
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static void audit(Connection connection, String partition, String action,
            String actorId, String approverId, String reason, String ticketId, Instant at)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO tenant_partition_change " +
                        "(partition_name,action,actor_id,approver_id,reason,ticket_id,occurred_at) " +
                        "VALUES(?,?,?,?,?,?,?)")) {
            statement.setString(1, partition);
            statement.setString(2, action);
            statement.setString(3, actorId);
            statement.setString(4, approverId);
            statement.setString(5, reason);
            statement.setString(6, ticketId);
            statement.setObject(7, at);
            statement.executeUpdate();
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 160
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException exception) {
            original.addSuppressed(exception);
        }
    }
}
