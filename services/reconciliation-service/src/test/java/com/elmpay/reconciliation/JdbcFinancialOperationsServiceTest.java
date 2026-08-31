package com.elmpay.reconciliation;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcFinancialOperationsServiceTest {
    private static final UUID TENANT =
            UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID FORGED_RUN =
            UUID.fromString("00000000-0000-0000-0000-000000000099");
    private static final Instant CUTOFF = Instant.parse("2026-08-30T02:00:00Z");
    private static final String SOURCE_DIGEST = "a".repeat(64);
    private static final String MANIFEST_DIGEST = "b".repeat(64);

    @Test
    void completedJobCannotReplayAResultThatHasNoExactlyBoundCompletedRun() {
        AtomicReference<String> replaySql = new AtomicReference<>();
        DataSource database = databaseWithForgedCompletedJob(replaySql);
        JdbcFinancialOperationsService service =
                JdbcFinancialOperationsService.reconciliationOnly(database,
                        Clock.fixed(Instant.parse("2026-08-30T03:00:00Z"), ZoneOffset.UTC),
                        Duration.ofMinutes(10));
        FinancialOperationsService.ReconciliationCommand command =
                new FinancialOperationsService.ReconciliationCommand(TENANT.toString(),
                        "stripe", LocalDate.of(2026, 8, 29), CUTOFF, SOURCE_DIGEST,
                        MANIFEST_DIGEST);

        assertThrows(IllegalStateException.class,
                () -> service.runReconciliation(command, java.util.List.of(), "worker-1"));
        assertTrue(replaySql.get().contains("FROM recon_run reconciliation_run"));
        assertTrue(replaySql.get().contains("reconciliation_run.state='completed'"));
        assertTrue(replaySql.get().contains("reconciliation_run.source_file_digest=?"));
        assertTrue(replaySql.get().contains("reconciliation_run.input_manifest_sha256=?"));
    }

    private static DataSource databaseWithForgedCompletedJob(
            AtomicReference<String> replaySql) {
        return (DataSource) Proxy.newProxyInstance(
                JdbcFinancialOperationsServiceTest.class.getClassLoader(),
                new Class<?>[] {DataSource.class}, (proxy, method, arguments) -> {
                    if ("getConnection".equals(method.getName())) {
                        return connection(replaySql);
                    }
                    return primitive(method.getReturnType());
                });
    }

    private static Connection connection(AtomicReference<String> replaySql) {
        return (Connection) Proxy.newProxyInstance(
                JdbcFinancialOperationsServiceTest.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, arguments) -> switch (
                        method.getName()) {
                    case "prepareStatement" -> statement((String) arguments[0], replaySql);
                    case "getAutoCommit" -> false;
                    case "setAutoCommit", "commit", "rollback", "close" -> null;
                    default -> primitive(method.getReturnType());
                });
    }

    private static PreparedStatement statement(String sql, AtomicReference<String> replaySql) {
        return (PreparedStatement) Proxy.newProxyInstance(
                JdbcFinancialOperationsServiceTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> switch (
                        method.getName()) {
                    case "execute" -> false;
                    case "executeUpdate" -> 0;
                    case "executeQuery" -> {
                        if (sql.contains("SELECT clock_timestamp()")) {
                            yield rows(java.util.List.of(row(
                                    1, Timestamp.from(Instant.parse("2026-08-30T03:00:00Z")))));
                        }
                        if (sql.contains("SELECT state,result_reference,fencing_token")) {
                            yield rows(java.util.List.of(row(
                                    1, "completed",
                                    2, FORGED_RUN.toString(),
                                    3, 7L,
                                    5, MANIFEST_DIGEST,
                                    6, Timestamp.from(CUTOFF),
                                    7, SOURCE_DIGEST)));
                        }
                        if (sql.contains("FROM recon_run reconciliation_run")) {
                            replaySql.set(sql);
                        }
                        yield rows(java.util.List.of());
                    }
                    case "close", "setObject", "setString", "setTimestamp" -> null;
                    default -> primitive(method.getReturnType());
                });
    }

    private static ResultSet rows(java.util.List<Map<Integer, Object>> values) {
        int[] index = {-1};
        return (ResultSet) Proxy.newProxyInstance(
                JdbcFinancialOperationsServiceTest.class.getClassLoader(),
                new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> {
                    if ("next".equals(method.getName())) {
                        return ++index[0] < values.size();
                    }
                    if ("close".equals(method.getName())) {
                        return null;
                    }
                    Object value = values.get(index[0]).get((Integer) arguments[0]);
                    return switch (method.getName()) {
                        case "getString" -> value == null ? null : value.toString();
                        case "getLong" -> ((Number) value).longValue();
                        case "getTimestamp" -> value;
                        default -> primitive(method.getReturnType());
                    };
                });
    }

    private static Map<Integer, Object> row(Object... values) {
        Map<Integer, Object> row = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            row.put((Integer) values[index], values[index + 1]);
        }
        return row;
    }

    private static Object primitive(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        return null;
    }
}
