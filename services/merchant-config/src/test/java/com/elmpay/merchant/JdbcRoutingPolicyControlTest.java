package com.elmpay.merchant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcRoutingPolicyControlTest {
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000028");
    private static final UUID PROJECT = UUID.fromString("10000000-0000-0000-0000-000000000028");
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");

    @Test
    void stableCanaryAllocationIsDeterministicAndNeverRandom() {
        int first = JdbcMerchantConfigurationRepository.stableCanaryBucket("payment-intent-28");
        int replay = JdbcMerchantConfigurationRepository.stableCanaryBucket("payment-intent-28");
        assertEquals(first, replay);
        assertTrue(first >= 0 && first < 10_000);
    }

    @Test
    void activationRequiresTwoDistinctDigestBoundApprovalsAndPersistsCanary() {
        RoutingDatabase denied = new RoutingDatabase(1);
        JdbcRoutingPolicyControl deniedControl = new JdbcRoutingPolicyControl(denied);
        assertThrows(SecurityException.class, () -> deniedControl.activate(TENANT, PROJECT,
                "stable-v1", "candidate-v2", 500, "release-operator",
                "bounded canary", "ticket-28", NOW));
        assertEquals(0, denied.commits);
        assertEquals(1, denied.rollbacks);

        RoutingDatabase approved = new RoutingDatabase(2);
        JdbcRoutingPolicyControl control = new JdbcRoutingPolicyControl(approved);
        control.activate(TENANT, PROJECT, "stable-v1", "candidate-v2", 500,
                "release-operator", "bounded canary", "ticket-28", NOW);
        assertEquals(1, approved.commits);
        assertEquals(0, approved.rollbacks);
        assertTrue(approved.sql.stream().anyMatch(value ->
                value.contains("INSERT INTO routing_policy_assignment")));
        assertTrue(approved.sql.stream().anyMatch(value ->
                value.contains("INSERT INTO routing_policy_change")));
    }

    @Test
    void invalidCanaryFailsBeforeDatabaseAndSimulationCannotMoveMoney() {
        RoutingDatabase database = new RoutingDatabase(2);
        JdbcRoutingPolicyControl control = new JdbcRoutingPolicyControl(database);
        assertThrows(IllegalArgumentException.class, () -> control.activate(TENANT, PROJECT,
                "stable-v1", "candidate-v2", 2_501, "release-operator",
                "too much", "ticket-28", NOW));
        assertEquals(0, database.connections);
        assertThrows(IllegalArgumentException.class, () -> new JdbcRoutingPolicyControl.Simulation(
                "stable-v1", UUID.randomUUID(), "a".repeat(64), true));
    }

    private static final class RoutingDatabase implements DataSource {
        private final int approvals;
        private final List<String> sql = new ArrayList<>();
        private int connections;
        private int commits;
        private int rollbacks;

        private RoutingDatabase(int approvals) {
            this.approvals = approvals;
        }

        @Override
        public Connection getConnection() {
            connections++;
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "setAutoCommit", "close" -> null;
                                case "getAutoCommit" -> false;
                                case "prepareStatement" -> prepared((String) arguments[0]);
                                case "commit" -> { commits++; yield null; }
                                case "rollback" -> { rollbacks++; yield null; }
                                case "isClosed" -> false;
                                case "unwrap" -> null;
                                case "isWrapperFor" -> false;
                                default -> defaultValue(method.getReturnType());
                            });
        }

        private PreparedStatement prepared(String query) {
            sql.add(query);
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "setString", "setInt", "setLong", "setBoolean",
                                        "setTimestamp", "close" -> null;
                                case "execute" -> true;
                                case "executeUpdate" -> 1;
                                case "executeQuery" -> query.contains("count(DISTINCT")
                                        ? approvalRows() : emptyRows();
                                default -> defaultValue(method.getReturnType());
                            });
        }

        private ResultSet approvalRows() {
            int[] cursor = {0};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "next" -> ++cursor[0] == 1;
                                case "getLong" -> (long) approvals;
                                case "close" -> null;
                                default -> defaultValue(method.getReturnType());
                            });
        }

        private ResultSet emptyRows() {
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "next" -> false;
                                case "close" -> null;
                                default -> defaultValue(method.getReturnType());
                            });
        }

        @Override public Connection getConnection(String username, String password) { return getConnection(); }
        @Override public <T> T unwrap(Class<T> iface) { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) { return false; }
        @Override public java.io.PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(java.io.PrintWriter out) {}
        @Override public void setLoginTimeout(int seconds) {}
        @Override public int getLoginTimeout() { return 0; }
        @Override public java.util.logging.Logger getParentLogger() {
            return java.util.logging.Logger.getGlobal();
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }
}
