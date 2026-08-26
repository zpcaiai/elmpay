package com.elmpay.merchant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.PrintWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcMerchantConfigurationRepositoryTest {
    private static final UUID TENANT = UUID.fromString("20000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("20000000-0000-0000-0000-000000000003");
    private static final UUID ACCOUNT = UUID.fromString("20000000-0000-0000-0000-000000000004");

    @Test
    void keepsTransactionLocalTenantContextActiveForEachQuery() {
        TrackingDataSource dataSource = new TrackingDataSource(false);
        JdbcMerchantConfigurationRepository repository =
                new JdbcMerchantConfigurationRepository(dataSource);

        assertEquals(false, repository.findAccount(TENANT, PROJECT, ACCOUNT).isPresent());
        assertEquals(List.of(), repository.eligibleRoutes(new RoutingRequest(TENANT, PROJECT,
                MERCHANT, "card", "USD", "US", 1_000, "intent-1")));

        assertEquals(2, dataSource.tenantBindings);
        assertEquals(List.of(false, false), dataSource.autoCommitAtQuery);
        assertEquals(List.of(true, true), dataSource.tenantActiveAtQuery);
        assertEquals(List.of(true, true), dataSource.readOnlyAtQuery);
        assertEquals(2, dataSource.commits);
        assertEquals(0, dataSource.rollbacks);
    }

    @Test
    void rollsBackWhenTenantScopedQueryFails() {
        TrackingDataSource dataSource = new TrackingDataSource(true);
        JdbcMerchantConfigurationRepository repository =
                new JdbcMerchantConfigurationRepository(dataSource);

        assertThrows(IllegalStateException.class,
                () -> repository.findAccount(TENANT, PROJECT, ACCOUNT));
        assertEquals(0, dataSource.commits);
        assertEquals(1, dataSource.rollbacks);
    }

    private static final class TrackingDataSource implements DataSource {
        private final boolean failQuery;
        private final List<Boolean> autoCommitAtQuery = new ArrayList<>();
        private final List<Boolean> tenantActiveAtQuery = new ArrayList<>();
        private final List<Boolean> readOnlyAtQuery = new ArrayList<>();
        private int tenantBindings;
        private int commits;
        private int rollbacks;

        private TrackingDataSource(boolean failQuery) {
            this.failQuery = failQuery;
        }

        @Override
        public Connection getConnection() {
            return proxy(Connection.class, new ConnectionHandler());
        }

        @Override
        public Connection getConnection(String username, String password) {
            return getConnection();
        }

        private final class ConnectionHandler implements InvocationHandler {
            private boolean autoCommit = true;
            private boolean tenantActive;
            private boolean readOnly;

            @Override
            public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
                return switch (method.getName()) {
                    case "setAutoCommit" -> {
                        autoCommit = (boolean) arguments[0];
                        yield null;
                    }
                    case "getAutoCommit" -> autoCommit;
                    case "setReadOnly" -> {
                        readOnly = (boolean) arguments[0];
                        yield null;
                    }
                    case "isReadOnly" -> readOnly;
                    case "prepareStatement" -> statement((String) arguments[0]);
                    case "commit" -> {
                        commits++;
                        tenantActive = false;
                        yield null;
                    }
                    case "rollback" -> {
                        rollbacks++;
                        tenantActive = false;
                        yield null;
                    }
                    case "close" -> null;
                    case "isClosed" -> false;
                    case "unwrap" -> throw new SQLException("not a wrapper");
                    case "isWrapperFor" -> false;
                    case "toString" -> "TrackingConnection";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    default -> defaultValue(method.getReturnType());
                };
            }

            private PreparedStatement statement(String sql) {
                boolean tenantStatement = sql.contains("set_config('app.tenant_id'");
                return proxy(PreparedStatement.class, (statement, method, arguments) -> {
                    return switch (method.getName()) {
                        case "execute" -> {
                            if (!tenantStatement || autoCommit) {
                                throw new SQLException("tenant context must be set in a transaction");
                            }
                            tenantBindings++;
                            tenantActive = true;
                            yield true;
                        }
                        case "executeQuery" -> {
                            autoCommitAtQuery.add(autoCommit);
                            tenantActiveAtQuery.add(tenantActive);
                            readOnlyAtQuery.add(readOnly);
                            if (autoCommit || !tenantActive) {
                                throw new SQLException("tenant context is not active for query");
                            }
                            if (failQuery) {
                                throw new SQLException("simulated query failure");
                            }
                            yield proxy(ResultSet.class, (result, resultMethod, resultArguments) ->
                                    switch (resultMethod.getName()) {
                                        case "next" -> false;
                                        case "close" -> null;
                                        default -> defaultValue(resultMethod.getReturnType());
                                    });
                        }
                        case "close", "setString", "setLong" -> null;
                        default -> defaultValue(method.getReturnType());
                    };
                });
            }
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0F;
        }
        return 0D;
    }
}
