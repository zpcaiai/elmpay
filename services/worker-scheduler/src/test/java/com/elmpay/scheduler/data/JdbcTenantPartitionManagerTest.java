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
    void createsBoundedMonthlyRangePartitionsUnderAnAdvisoryLock() {
        RecordingDatabase database = new RecordingDatabase(false, true);
        JdbcTenantPartitionManager manager = new JdbcTenantPartitionManager(database,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(2, manager.ensureMonthlyPartitions(YearMonth.of(2026, 8), 2,
                "scheduler-one", "scheduled partition precreation", "ticket-123"));
        assertTrue(database.sql.stream().anyMatch(value -> value.contains("pg_advisory_xact_lock")));
        assertTrue(database.sql.stream().anyMatch(value -> value.contains(
                "CREATE TABLE tenant_archive_fact_202608 PARTITION OF tenant_archive_fact " +
                        "FOR VALUES FROM ('2026-08-01') TO ('2026-09-01')")));
        assertTrue(database.sql.stream().anyMatch(value -> value.contains(
                "CREATE TABLE tenant_archive_fact_202609 PARTITION OF tenant_archive_fact")));
        assertThrows(IllegalArgumentException.class, () -> manager.ensureMonthlyPartitions(
                YearMonth.of(2026, 8), 25, "actor", "reason", "ticket"));
    }

    @Test
    void detachRequiresPastPartitionFourEyesAndVerifiedExternalReceipt() {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000013");
        JdbcTenantPartitionManager missingReceipt = new JdbcTenantPartitionManager(
                new RecordingDatabase(true, false), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThrows(IllegalStateException.class, () -> missingReceipt.detachArchivedPartition(
                tenant, YearMonth.of(2026, 6), "operator-a", "approver-b", "archive", "ticket"));
        JdbcTenantPartitionManager manager = new JdbcTenantPartitionManager(
                new RecordingDatabase(true, true), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThrows(IllegalArgumentException.class, () -> manager.detachArchivedPartition(
                tenant, YearMonth.of(2026, 6), "operator-a", "operator-a", "archive", "ticket"));
        manager.detachArchivedPartition(tenant, YearMonth.of(2026, 6), "operator-a",
                "approver-b", "archive verified", "ticket-456");
    }

    private static final class RecordingDatabase implements DataSource {
        private final List<String> sql = new ArrayList<>();
        private final boolean partitionExists;
        private final boolean receiptExists;

        private RecordingDatabase(boolean partitionExists, boolean receiptExists) {
            this.partitionExists = partitionExists;
            this.receiptExists = receiptExists;
        }

        @Override
        public Connection getConnection() {
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "prepareStatement" -> prepared((String) arguments[0]);
                        case "createStatement" -> statement();
                        case "getAutoCommit" -> false;
                        case "setAutoCommit", "commit", "rollback", "close" -> null;
                        case "isClosed" -> false;
                        case "unwrap" -> null;
                        case "isWrapperFor" -> false;
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private Statement statement() {
            return (Statement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Statement.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "execute" -> { sql.add((String) arguments[0]); yield true; }
                        case "close" -> null;
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private PreparedStatement prepared(String query) {
            sql.add(query);
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "setString", "setObject", "close" -> null;
                        case "execute" -> true;
                        case "executeUpdate" -> 1;
                        case "executeQuery" -> query.contains("to_regclass")
                                ? catalogRow(partitionExists) : rows(receiptExists);
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private ResultSet rows(boolean exists) {
            int[] cursor = {0};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "next" -> ++cursor[0] == 1 && exists;
                        case "getBoolean" -> exists;
                        case "getString" -> switch ((Integer) arguments[0]) {
                            case 1, 2 -> "a".repeat(64);
                            case 3 -> "external-verifier";
                            case 4 -> "external-receipt";
                            default -> throw new IllegalArgumentException();
                        };
                        case "close" -> null;
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }

        private ResultSet catalogRow(boolean exists) {
            int[] cursor = {0};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "next" -> ++cursor[0] == 1;
                        case "getBoolean" -> exists;
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
