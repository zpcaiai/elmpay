package com.elmpay.admin;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

final class JdbcAdminDomainCommandQueueLeaseTest {
    private static final Instant CREATED = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void retryDelegatesClockLeaseAndExpiryChecksToNarrowDatabaseApi() throws Exception {
        List<String> statements = new ArrayList<>();
        Connection connection = connection(CREATED.plusSeconds(31), statements);
        AdminDomainCommandQueue.Claim claim = claim(CREATED.plusSeconds(30),
                CREATED.plusSeconds(60));
        new JdbcAdminDomainCommandQueue().retry(
                connection, claim, "DATABASE_FAILED", "a".repeat(64),
                CREATED.plusSeconds(40), false, CREATED.plusSeconds(20));
        assertTrue(statements.stream().anyMatch(
                sql -> sql.contains("elmpay_admin_retry_command")));
        assertTrue(statements.stream().noneMatch(sql -> sql.contains("UPDATE admin_domain_command")));
    }

    @Test
    void blockCannotBypassDatabaseLeaseFenceWithCallerTimestamp() throws Exception {
        List<String> statements = new ArrayList<>();
        Connection connection = connection(CREATED.plusSeconds(61), statements);
        AdminDomainCommandQueue.Claim claim = claim(CREATED.plusSeconds(90),
                CREATED.plusSeconds(60));
        new JdbcAdminDomainCommandQueue().block(
                connection, claim, "INVALID_BINDING", "b".repeat(64),
                CREATED.plusSeconds(20));
        assertTrue(statements.stream().anyMatch(
                sql -> sql.contains("elmpay_admin_block_command")));
        assertTrue(statements.stream().noneMatch(sql -> sql.contains("UPDATE admin_domain_command")));
    }

    @Test
    void retryWindowDecisionIsMadeOnlyInsideDatabaseFunction() throws Exception {
        List<String> statements = new ArrayList<>();
        Connection connection = connection(CREATED.plusSeconds(10), statements);
        AdminDomainCommandQueue.Claim claim = claim(CREATED.plusSeconds(30),
                CREATED.plusSeconds(20));
        new JdbcAdminDomainCommandQueue().retry(connection, claim, "DATABASE_FAILED",
                "c".repeat(64), CREATED.plusSeconds(20), true, CREATED.plusSeconds(5));
        assertTrue(statements.stream().anyMatch(
                sql -> sql.contains("elmpay_admin_retry_command")));
        assertTrue(statements.stream().noneMatch(
                sql -> sql.contains("INSERT INTO admin_domain_command")
                        || sql.contains("UPDATE admin_domain_command")));
    }

    private static AdminDomainCommandQueue.Claim claim(Instant leaseUntil, Instant expiresAt) {
        UUID id = UUID.fromString("10000000-0000-4000-8000-000000000001");
        UUID tenant = UUID.fromString("20000000-0000-4000-8000-000000000001");
        UUID project = UUID.fromString("30000000-0000-4000-8000-000000000001");
        String digest = AdminDomainCommand.computeCommandDigest(id, tenant, project,
                "1".repeat(64), AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.PAYMENT, id.toString(), "2".repeat(64),
                "3".repeat(64), 2, "4".repeat(64), "5".repeat(64), expiresAt, 7,
                CREATED);
        AdminDomainCommand command = new AdminDomainCommand(id, tenant, project,
                "1".repeat(64), digest, AdminDomainCommand.Kind.REFUND_OVERRIDE,
                AdminDomainCommand.OperationCode.REFUND_OVERRIDE,
                AdminDomainCommand.ConsumerGroup.PAYMENT, id.toString(), "2".repeat(64),
                "3".repeat(64), 2, "4".repeat(64), "5".repeat(64), expiresAt, 7,
                CREATED);
        return new AdminDomainCommandQueue.Claim(command, "worker-123", 1, leaseUntil, 1,
                AdminDomainCommandQueue.State.PENDING);
    }

    private static Connection connection(Instant databaseNow, List<String> statements) {
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, arguments) -> switch (
                        method.getName()) {
                    case "getAutoCommit" -> false;
                    case "prepareStatement" -> statement((String) arguments[0], databaseNow,
                            statements);
                    case "isWrapperFor" -> false;
                    case "unwrap" -> throw new SQLException("not a wrapper");
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static PreparedStatement statement(String sql, Instant databaseNow,
            List<String> statements) {
        statements.add(sql);
        return (PreparedStatement) Proxy.newProxyInstance(
                PreparedStatement.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> switch (
                        method.getName()) {
                    case "execute" -> true;
                    case "executeQuery" -> result(databaseNow);
                    case "isWrapperFor" -> false;
                    case "unwrap" -> throw new SQLException("not a wrapper");
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static ResultSet result(Instant databaseNow) {
        AtomicBoolean first = new AtomicBoolean(true);
        return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(),
                new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (
                        method.getName()) {
                    case "next" -> first.getAndSet(false);
                    case "getTimestamp" -> Timestamp.from(databaseNow);
                    case "isWrapperFor" -> false;
                    case "unwrap" -> throw new SQLException("not a wrapper");
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static Object primitiveDefault(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        throw new AssertionError(type);
    }
}
