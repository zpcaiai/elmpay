package com.elmpay.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AuditEventTest {
    @Test
    void digestIsDeterministicAndSensitiveDataIsRejected() {
        UUID id = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000002");
        AuditEvent event = new AuditEvent(id, tenant, "operator-a", "refund.approve", "refund",
                "ref-1", "customer request", "TICKET-1", Map.of("state", "pending"),
                Map.of("state", "approved"), "corr-1", Instant.EPOCH);
        assertEquals(event.canonicalDigest(), event.canonicalDigest());
        assertThrows(IllegalArgumentException.class,
                () -> new AuditEvent(id, tenant, "actor", "x", "y", "z", null, null,
                        Map.of("cvv", "123"), Map.of(), "corr", Instant.EPOCH));
    }

    @Test
    void rlsIdentityIsTransactionLocalAndRejectsAutocommit() throws Exception {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000002");
        List<String> calls = new ArrayList<>();
        Connection transaction = connection(false, calls);

        JdbcAuditLog.setTenantContext(transaction, tenant);

        assertTrue(calls.getFirst().contains("set_config('app.tenant_id', ?, true)"));
        assertEquals(tenant.toString(), calls.get(1));
        assertThrows(SQLException.class,
                () -> JdbcAuditLog.setTenantContext(connection(true, new ArrayList<>()), tenant));
    }

    private static Connection connection(boolean autoCommit, List<String> calls) {
        return (Connection) Proxy.newProxyInstance(AuditEventTest.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAutoCommit" -> autoCommit;
                    case "prepareStatement" -> {
                        calls.add((String) args[0]);
                        yield statement(calls);
                    }
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static PreparedStatement statement(List<String> calls) {
        return (PreparedStatement) Proxy.newProxyInstance(AuditEventTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "setString" -> {
                        calls.add((String) args[1]);
                        yield null;
                    }
                    case "execute" -> true;
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                });
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
