package com.elmpay.scheduler.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcTenantPartitionManagerTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");

    @Test
    void invokesOnlyBoundedDedicatedPartitionPrecreationCapability() {
        RecordingDatabase database = new RecordingDatabase();
        JdbcTenantPartitionManager manager = new JdbcTenantPartitionManager(database,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(2, manager.ensureMonthlyPartitions(YearMonth.of(2026, 8), 2,
                "scheduler-one", "scheduled partition precreation", "ticket-123"));
        assertTrue(database.sql.stream().anyMatch(value -> value.contains(
                "elmpay_ensure_archive_partitions")));
        assertTrue(database.sql.stream().noneMatch(value -> value.contains("CREATE TABLE")));
        assertTrue(database.sql.stream().noneMatch(value -> value.contains("DETACH PARTITION")));
        assertThrows(IllegalArgumentException.class, () -> manager.ensureMonthlyPartitions(
                YearMonth.of(2026, 8), 25, "actor", "reason", "ticket"));
    }

    @Test
    void legacySingleTenantDetachIsPermanentlyDisabled() {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000013");
        JdbcTenantPartitionManager manager = new JdbcTenantPartitionManager(
                new RecordingDatabase(), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThrows(UnsupportedOperationException.class,
                () -> manager.detachArchivedPartition(tenant, YearMonth.of(2026, 6),
                        "operator-a", "approver-b", "archive verified", "ticket-456"));
    }

    private static final class RecordingDatabase implements DataSource {
        private final List<String> sql = new ArrayList<>();

        @Override
        public Connection getConnection() {
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "prepareStatement" -> prepared((String) arguments[0]);
                        case "getAutoCommit" -> false;
                        case "setAutoCommit", "commit", "rollback", "close" -> null;
                        case "isClosed" -> false;
                        case "unwrap" -> null;
                        case "isWrapperFor" -> false;
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private PreparedStatement prepared(String query) {
            sql.add(query);
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "setString", "setObject", "setInt", "close" -> null;
                        case "execute" -> true;
                        case "executeUpdate" -> 1;
                        case "executeQuery" -> rows(query.contains("current_user") ? 1 : 2);
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private ResultSet rows(int value) {
            int[] cursor = {0};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "next" -> ++cursor[0] == 1;
                        case "getBoolean" -> value == 1;
                        case "getInt" -> value;
                        case "close" -> null;
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        @Override public Connection getConnection(String username, String password) { return getConnection(); }
        @Override public <T> T unwrap(Class<T> iface) { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) { return false; }
        @Override public java.io.PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(java.io.PrintWriter out) {}
        @Override public void setLoginTimeout(int seconds) {}
        @Override public int getLoginTimeout() { return 0; }
        @Override public java.util.logging.Logger getParentLogger() { return java.util.logging.Logger.getGlobal(); }
    }
}
