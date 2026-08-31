package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcReconciliationScheduleStoreTest {
    private static final UUID TENANT =
            UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void restartCursorAdvancesExactlyOnceAndRetainsOldestBacklogDay() {
        Database database = new Database();
        JdbcReconciliationScheduleStore first = store(database);
        LocalDate day = LocalDate.of(2026, 8, 28);
        database.oldestSourceDate = day;
        assertEquals(day, first.next(TENANT, "stripe", day));
        first.completed(TENANT, "stripe", day);
        first.completed(TENANT, "stripe", day); // other-replica replay is a no-op
        assertThrows(IllegalStateException.class,
                () -> first.completed(TENANT, "stripe", day.minusDays(1)));
        assertNull(first.next(TENANT, "stripe", day));

        JdbcReconciliationScheduleStore restarted = store(database);
        assertEquals(day.plusDays(1), restarted.next(TENANT, "stripe", day.plusDays(3)));
        assertThrows(IllegalStateException.class,
                () -> restarted.completed(TENANT, "stripe", day.plusDays(2)));
        assertEquals(1, database.fencingToken);
    }

    @Test
    void providerWithoutGovernedProductionCapabilityDoesNotCreateWork() {
        Database database = new Database();
        database.providerEligible = false;
        LocalDate day = LocalDate.of(2026, 8, 28);
        assertNull(store(database).next(TENANT, "stripe", day));
        assertNull(database.next);
    }

    @Test
    void productionEligibilityRequiresAnActiveProviderAccount() {
        Database database = new Database();
        database.oldestSourceDate = LocalDate.of(2026, 8, 28);
        store(database).next(TENANT, "stripe", database.oldestSourceDate);
        assertEquals("active", database.requiredProviderAccountStatus);
    }

    @Test
    void eligibleProviderWithoutImmutableSourceFactsDoesNotFabricateAWorkDay() {
        Database database = new Database();
        LocalDate day = LocalDate.of(2026, 8, 28);
        assertNull(store(database).next(TENANT, "stripe", day));
        assertNull(database.next);
    }

    @Test
    void firstCursorStartsAtOldestImmutableSourceInsteadOfLatestEligibleDay() {
        Database database = new Database();
        LocalDate oldest = LocalDate.of(2026, 8, 24);
        database.oldestSourceDate = oldest;
        assertEquals(oldest, store(database).next(TENANT, "stripe",
                LocalDate.of(2026, 8, 28)));
    }

    @Test
    void failureIsDurableFencedAndDoesNotAdvanceTheCursor() {
        Database database = new Database();
        LocalDate day = LocalDate.of(2026, 8, 28);
        database.oldestSourceDate = day;
        JdbcReconciliationScheduleStore store = store(database);
        assertEquals(day, store.next(TENANT, "stripe", day));
        String digest = "a".repeat(64);
        store.failed(TENANT, "stripe", day, "MISSING_SOURCE", digest);
        assertEquals(day, database.next);
        assertEquals(1, database.failureCount);
        assertEquals("MISSING_SOURCE", database.failureCode);
        assertEquals(digest, database.failureDigest);
        assertEquals(1, database.fencingToken);
    }

    private static JdbcReconciliationScheduleStore store(Database database) {
        return new JdbcReconciliationScheduleStore(database.dataSource(), Clock.fixed(
                Instant.parse("2026-08-30T03:00:00Z"), ZoneOffset.UTC));
    }

    private static final class Database {
        private LocalDate next;
        private LocalDate oldestSourceDate;
        private int fencingToken;
        private int failureCount;
        private String failureCode;
        private String failureDigest;
        private boolean providerEligible = true;
        private String requiredProviderAccountStatus;

        DataSource dataSource() {
            return (DataSource) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {DataSource.class}, (proxy, method, arguments) ->
                            "getConnection".equals(method.getName()) ? connection() : null);
        }

        private Connection connection() {
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) -> switch (
                            method.getName()) {
                        case "prepareStatement" -> statement((String) arguments[0]);
                        case "setAutoCommit", "commit", "rollback", "close" -> null;
                        default -> primitive(method.getReturnType());
                    });
        }

        private PreparedStatement statement(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> {
                        if (method.getName().startsWith("set") && arguments != null
                                && arguments.length >= 2) {
                            parameters.put((Integer) arguments[0], arguments[1]);
                            return null;
                        }
                        return switch (method.getName()) {
                            case "execute" -> false;
                            case "executeQuery" -> {
                                if (sql.contains("FROM provider_account account")) {
                                    if (sql.contains("account.status='active'")) {
                                        requiredProviderAccountStatus = "active";
                                    }
                                    yield presence(providerEligible);
                                }
                                if (sql.contains("min(candidate.business_date)")) {
                                    yield scalar(oldestSourceDate);
                                }
                                yield result(next);
                            }
                            case "executeUpdate" -> {
                                if (sql.contains("INSERT INTO reconciliation_schedule_cursor")) {
                                    if (next == null) next = (LocalDate) parameters.get(3);
                                    yield 1;
                                }
                                if (sql.contains("UPDATE reconciliation_schedule_cursor")) {
                                    if (sql.contains("failure_count=failure_count+1")) {
                                        if (!next.equals(parameters.get(5))) yield 0;
                                        failureCount++;
                                        failureCode = (String) parameters.get(1);
                                        failureDigest = (String) parameters.get(2);
                                        fencingToken++;
                                        yield 1;
                                    }
                                    if (!next.equals(parameters.get(4))) yield 0;
                                    next = (LocalDate) parameters.get(1);
                                    fencingToken++;
                                    yield 1;
                                }
                                yield 0;
                            }
                            case "close" -> null;
                            default -> primitive(method.getReturnType());
                        };
                    });
        }

        private ResultSet result(LocalDate value) {
            boolean[] visited = {false};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (
                            method.getName()) {
                        case "next" -> {
                            boolean present = value != null && !visited[0];
                            visited[0] = true;
                            yield present;
                        }
                        case "getObject" -> value;
                        case "close" -> null;
                        default -> primitive(method.getReturnType());
                    });
        }

        private ResultSet presence(boolean present) {
            boolean[] visited = {false};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (
                            method.getName()) {
                        case "next" -> {
                            boolean value = present && !visited[0];
                            visited[0] = true;
                            yield value;
                        }
                        case "close" -> null;
                        default -> primitive(method.getReturnType());
                    });
        }

        private ResultSet scalar(LocalDate value) {
            boolean[] visited = {false};
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> switch (
                            method.getName()) {
                        case "next" -> {
                            boolean present = !visited[0];
                            visited[0] = true;
                            yield present;
                        }
                        case "getObject" -> value;
                        case "close" -> null;
                        default -> primitive(method.getReturnType());
                    });
        }

        private static Object primitive(Class<?> type) {
            if (type == boolean.class) return false;
            if (type == int.class) return 0;
            if (type == long.class) return 0L;
            return null;
        }
    }
}
