package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.scheduler.JdbcWorkerScopeRegistry.Scope;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcWorkerScopeRegistryTest {
    private static final Scope FIRST = new Scope(
            UUID.fromString("00000000-0000-0000-0000-000000000001"),
            UUID.fromString("00000000-0000-0000-0000-000000000011"));
    private static final Scope SECOND = new Scope(
            UUID.fromString("00000000-0000-0000-0000-000000000001"),
            UUID.fromString("00000000-0000-0000-0000-000000000012"));
    private static final Scope THIRD = new Scope(
            UUID.fromString("00000000-0000-0000-0000-000000000002"),
            UUID.fromString("00000000-0000-0000-0000-000000000021"));

    @Test
    void pagesDeterministicallyAndWrapsAfterTheLastScope() {
        JdbcWorkerScopeRegistry registry = new JdbcWorkerScopeRegistry(
                database(List.of(FIRST, SECOND, THIRD), null));
        assertEquals(List.of(FIRST, SECOND), registry.activeScopes(2));
        assertEquals(List.of(THIRD), registry.activeScopes(2, SECOND));
        assertEquals(List.of(FIRST, SECOND), registry.activeScopes(2, THIRD));
        assertThrows(IllegalArgumentException.class, () -> registry.activeScopes(0));
    }

    @Test
    void schemaVerificationFailsClosedForOneMissingTable() {
        new JdbcWorkerScopeRegistry(database(List.of(), null)).verifyRequiredSchema();
        JdbcWorkerScopeRegistry missing = new JdbcWorkerScopeRegistry(
                database(List.of(), "outbox_event"));
        assertThrows(IllegalStateException.class, missing::verifyRequiredSchema);
        JdbcWorkerScopeRegistry noDiscoveryGrant = new JdbcWorkerScopeRegistry(
                database(List.of(), "elmpay_active_worker_scopes"));
        assertThrows(IllegalStateException.class, noDiscoveryGrant::verifyRequiredSchema);
    }

    @Test
    void databaseFailureIsClassifiedWithoutReturningAnEmptyWorkSet() {
        DataSource unavailable = proxy(DataSource.class, (target, method, arguments) -> {
            if (method.getName().equals("getConnection")) {
                throw new SQLException("host detail must not be surfaced as success");
            }
            return defaultValue(method.getReturnType());
        });
        JdbcWorkerScopeRegistry registry = new JdbcWorkerScopeRegistry(unavailable);
        assertThrows(IllegalStateException.class, () -> registry.activeScopes(10));
        assertThrows(IllegalStateException.class, registry::verifyRequiredSchema);
    }

    private static DataSource database(List<Scope> scopes, String missingTable) {
        return proxy(DataSource.class, (target, method, arguments) -> {
            if (method.getName().equals("getConnection")) {
                return connection(scopes, missingTable);
            }
            return defaultValue(method.getReturnType());
        });
    }

    private static Connection connection(List<Scope> scopes, String missingTable) {
        return proxy(Connection.class, (target, method, arguments) -> {
            if (method.getName().equals("prepareStatement")) {
                return statement((String) arguments[0], scopes, missingTable);
            }
            return defaultValue(method.getReturnType());
        });
    }

    private static PreparedStatement statement(String sql, List<Scope> scopes,
            String missingTable) {
        Map<Integer, Object> parameters = new HashMap<>();
        return proxy(PreparedStatement.class, (target, method, arguments) -> {
            if (method.getName().startsWith("set") && arguments != null
                    && arguments.length >= 2 && arguments[0] instanceof Integer index) {
                parameters.put(index, arguments[1]);
                return null;
            }
            if (method.getName().equals("executeQuery")) {
                if (sql.contains("pg_roles")) {
                    return booleanResult(true);
                }
                if (sql.contains("to_regprocedure")) {
                    return booleanResult(!"elmpay_active_worker_scopes".equals(missingTable));
                }
                if (sql.contains("to_regclass")) {
                    String table = (String) parameters.get(1);
                    return booleanResult(!table.equals(missingTable));
                }
                if (sql.contains("information_schema.columns")) {
                    return booleanResult(true);
                }
                Scope after = parameters.get(1) == null ? null : new Scope(
                        (UUID) parameters.get(1), (UUID) parameters.get(2));
                int maximum = (Integer) parameters.get(3);
                List<Scope> page = new ArrayList<>();
                for (Scope scope : scopes) {
                    if (after == null || compare(scope, after) > 0) {
                        page.add(scope);
                    }
                    if (page.size() == maximum) {
                        break;
                    }
                }
                return scopeResult(page);
            }
            return defaultValue(method.getReturnType());
        });
    }

    private static ResultSet booleanResult(boolean value) {
        AtomicRow cursor = new AtomicRow(1);
        return proxy(ResultSet.class, (target, method, arguments) -> switch (method.getName()) {
            case "next" -> cursor.next();
            case "getBoolean" -> value;
            default -> defaultValue(method.getReturnType());
        });
    }

    private static ResultSet scopeResult(List<Scope> scopes) {
        AtomicRow cursor = new AtomicRow(scopes.size());
        return proxy(ResultSet.class, (target, method, arguments) -> {
            if (method.getName().equals("next")) {
                return cursor.next();
            }
            if (method.getName().equals("getObject")) {
                Scope scope = scopes.get(cursor.index());
                return "tenant_id".equals(arguments[0]) ? scope.tenantId() : scope.projectId();
            }
            return defaultValue(method.getReturnType());
        });
    }

    private static int compare(Scope left, Scope right) {
        int tenants = left.tenantId().compareTo(right.tenantId());
        return tenants != 0 ? tenants : left.projectId().compareTo(right.projectId());
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }

    private static final class AtomicRow {
        private final int count;
        private int index = -1;

        private AtomicRow(int count) {
            this.count = count;
        }

        boolean next() {
            index++;
            return index < count;
        }

        int index() {
            return index;
        }
    }
}
