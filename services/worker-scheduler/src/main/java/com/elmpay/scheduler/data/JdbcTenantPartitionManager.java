package com.elmpay.scheduler.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** Client for the narrow, separately credentialed partition-precreation capability. */
public final class JdbcTenantPartitionManager {
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
        if (!"scheduled partition precreation".equals(reason)
                || !firstMonth.equals(YearMonth.from(clock.instant().atZone(ZoneOffset.UTC)))) {
            throw new IllegalArgumentException(
                    "partition precreation must start at the current UTC month");
        }
        if (count < 1 || count > MAX_CREATE_MONTHS) {
            throw new IllegalArgumentException("partition count must be 1..24");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                requirePrecreatorRole(connection);
                int created;
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT public.elmpay_ensure_archive_partitions(?,?,?,?)")) {
                    statement.setObject(1, firstMonth.atDay(1));
                    statement.setInt(2, count);
                    statement.setString(3, actorId);
                    statement.setString(4, ticketId);
                    try (ResultSet result = statement.executeQuery()) {
                        if (!result.next()) {
                            throw new SQLException("partition capability returned no result");
                        }
                        created = result.getInt(1);
                        if (created < 0 || created > count || result.next()) {
                            throw new SQLException("partition capability returned an invalid count");
                        }
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
        Objects.requireNonNull(month, "month");
        throw new UnsupportedOperationException(
                "single-tenant receipt detach is permanently disabled; use the separate "
                        + "all-tenant signed-release detacher");
    }

    private static void requirePrecreatorRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT current_user = 'elmpay_partition_precreator' "
                        + "AND session_user = current_user")) {
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "partition precreation requires its exact dedicated role");
                }
            }
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
