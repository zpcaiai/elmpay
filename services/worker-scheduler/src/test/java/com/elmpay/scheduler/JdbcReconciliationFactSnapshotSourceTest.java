package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class JdbcReconciliationFactSnapshotSourceTest {
    private static final UUID TENANT =
            UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT =
            UUID.fromString("00000000-0000-0000-0000-000000000011");
    private static final Instant CUTOFF = Instant.parse("2026-08-30T02:00:00Z");
    private static final ReconciliationSchedulerJob.SnapshotRequest REQUEST =
            new ReconciliationSchedulerJob.SnapshotRequest(TENANT, "stripe",
                    LocalDate.of(2026, 8, 29), CUTOFF);

    @Test
    void persistsAndRestartLoadsTheSameCanonicalFourSourceSnapshot() {
        ScriptedDatabase database = new ScriptedDatabase();
        JdbcReconciliationFactSnapshotSource source = source(database, 100);
        ReconciliationSchedulerJob.FactSnapshot first = source.snapshot(REQUEST);
        ReconciliationSchedulerJob.FactSnapshot replay = source.snapshot(REQUEST);

        assertEquals(4, first.facts().size());
        assertEquals(first.sourceSetDigest(), replay.sourceSetDigest());
        assertEquals(first.inputManifestDigest(), replay.inputManifestDigest());
        assertEquals(first.facts(), replay.facts());
        assertEquals(Connection.TRANSACTION_REPEATABLE_READ, database.isolation);
        assertEquals(2, database.commits.get());
        assertTrue(database.tenantParameters.stream().allMatch(TENANT::equals));
    }

    @Test
    void emptyOversizedAmbiguousAndTamperedSnapshotsFailClosed() {
        ScriptedDatabase empty = new ScriptedDatabase();
        empty.emitFacts = false;
        assertThrows(IllegalStateException.class, () -> source(empty, 100).snapshot(REQUEST));

        ScriptedDatabase missingBank = new ScriptedDatabase();
        missingBank.omittedStatementKind = "BANK";
        assertThrows(IllegalStateException.class,
                () -> source(missingBank, 100).snapshot(REQUEST));

        ScriptedDatabase oversized = new ScriptedDatabase();
        assertThrows(IllegalStateException.class, () -> source(oversized, 2).snapshot(REQUEST));

        ScriptedDatabase ambiguous = new ScriptedDatabase();
        ambiguous.platformProject = UUID.randomUUID();
        assertThrows(IllegalStateException.class, () -> source(ambiguous, 100).snapshot(REQUEST));

        ScriptedDatabase tampered = new ScriptedDatabase();
        JdbcReconciliationFactSnapshotSource source = source(tampered, 100);
        source.snapshot(REQUEST);
        tampered.members.getFirst().put(7, 101L);
        assertThrows(IllegalStateException.class, () -> source.snapshot(REQUEST));

        ScriptedDatabase countTampered = new ScriptedDatabase();
        JdbcReconciliationFactSnapshotSource countSource = source(countTampered, 100);
        countSource.snapshot(REQUEST);
        countTampered.snapshot.put(9, 2);
        assertThrows(IllegalStateException.class, () -> countSource.snapshot(REQUEST));
    }

    @Test
    void futureCutoffIsRejectedBeforeOpeningTheDatabase() {
        ScriptedDatabase database = new ScriptedDatabase();
        var future = new ReconciliationSchedulerJob.SnapshotRequest(TENANT, "stripe",
                LocalDate.of(2026, 8, 30), Instant.parse("2026-08-31T02:00:00Z"));
        assertThrows(IllegalArgumentException.class, () -> source(database, 100).snapshot(future));
        assertEquals(0, database.connections.get());
    }

    private static JdbcReconciliationFactSnapshotSource source(ScriptedDatabase database,
            int maximumFacts) {
        return new JdbcReconciliationFactSnapshotSource(database.dataSource(),
                Clock.fixed(Instant.parse("2026-08-30T03:00:00Z"), ZoneOffset.UTC), maximumFacts);
    }

    private static final class ScriptedDatabase {
        private final AtomicInteger connections = new AtomicInteger();
        private final AtomicInteger commits = new AtomicInteger();
        private final List<UUID> tenantParameters = new ArrayList<>();
        private final List<Map<Integer, Object>> members = new ArrayList<>();
        private Map<Integer, Object> snapshot;
        private int isolation;
        private boolean emitFacts = true;
        private String omittedStatementKind;
        private UUID platformProject = PROJECT;

        DataSource dataSource() {
            return (DataSource) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {DataSource.class}, (proxy, method, arguments) -> {
                        if ("getConnection".equals(method.getName())) {
                            connections.incrementAndGet();
                            return connection();
                        }
                        return defaultValue(method.getReturnType());
                    });
        }

        private Connection connection() {
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) -> {
                        return switch (method.getName()) {
                            case "prepareStatement" -> statement((String) arguments[0]);
                            case "setTransactionIsolation" -> {
                                isolation = (Integer) arguments[0];
                                yield null;
                            }
                            case "commit" -> {
                                commits.incrementAndGet();
                                yield null;
                            }
                            case "setAutoCommit", "rollback", "close" -> null;
                            case "isClosed" -> false;
                            default -> defaultValue(method.getReturnType());
                        };
                    });
        }

        private PreparedStatement statement(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            List<Map<Integer, Object>> batches = new ArrayList<>();
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> {
                        String name = method.getName();
                        if (name.startsWith("set") && arguments != null
                                && arguments.length >= 2 && arguments[0] instanceof Integer index) {
                            if (!"setMaxRows".equals(name)) {
                                parameters.put(index, arguments[1]);
                                if (arguments[1] instanceof UUID tenant && TENANT.equals(tenant)) {
                                    tenantParameters.add(tenant);
                                }
                            }
                            return null;
                        }
                        return switch (name) {
                            case "addBatch" -> {
                                batches.add(new HashMap<>(parameters));
                                yield null;
                            }
                            case "executeBatch" -> {
                                if (sql.contains("INSERT INTO reconciliation_fact_snapshot_member")) {
                                    members.clear();
                                    batches.forEach(batch -> members.add(new HashMap<>(batch)));
                                }
                                yield new int[batches.size()];
                            }
                            case "executeUpdate" -> {
                                if (sql.contains("INSERT INTO reconciliation_fact_snapshot\n")) {
                                    snapshot = new HashMap<>(parameters);
                                }
                                yield 1;
                            }
                            case "executeQuery" -> result(rows(sql, parameters));
                            case "execute" -> false;
                            case "close" -> null;
                            default -> defaultValue(method.getReturnType());
                        };
                    });
        }

        private List<Map<Object, Object>> rows(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("FROM reconciliation_fact_snapshot\n")) {
                if (snapshot == null) {
                    return List.of();
                }
                return List.of(row(
                        1, snapshot.get(1), 2, snapshot.get(6), 3, snapshot.get(7),
                        4, snapshot.get(8), 5, snapshot.get(9), 6, snapshot.get(10),
                        7, snapshot.get(11), 8, snapshot.get(12), "id", snapshot.get(1),
                        "source_set_sha256", snapshot.get(6),
                        "input_manifest_sha256", snapshot.get(7),
                        "canonical_manifest", snapshot.get(8),
                        "business_count", snapshot.get(9),
                        "platform_count", snapshot.get(10),
                        "provider_count", snapshot.get(11),
                        "bank_count", snapshot.get(12)));
            }
            if (sql.contains("FROM reconciliation_fact_snapshot_member")) {
                List<Map<Object, Object>> values = new ArrayList<>();
                for (Map<Integer, Object> member : members) {
                    values.add(row(1, member.get(4), 2, member.get(5), 3, member.get(6),
                            4, member.get(7), 5, member.get(8), 6, member.get(9),
                            7, member.get(10)));
                }
                return values;
            }
            if (!emitFacts) {
                return List.of();
            }
            if (sql.contains("JOIN ledger_transaction")) {
                return List.of(fact(platformProject, "2".repeat(64)));
            }
            if (sql.contains("FROM outbox_event e")) {
                return List.of(fact(PROJECT, "1".repeat(64)));
            }
            if (sql.contains("FROM statement_file sf")) {
                String kind = String.valueOf(parameters.get(2));
                if (kind.equals(omittedStatementKind)) {
                    return List.of();
                }
                return List.of(fact(null, ("PROVIDER".equals(kind) ? "3" : "4").repeat(64)));
            }
            return List.of();
        }

        private static Map<Object, Object> fact(UUID project, String digest) {
            return row("project_id", project, "reference", "a".repeat(64),
                    "event_type", "CAPTURE", "amount_minor", 100L, "currency", "USD",
                    "occurred_at", Timestamp.from(Instant.parse("2026-08-29T12:00:00Z")),
                    "source_digest", digest);
        }

        private ResultSet result(List<Map<Object, Object>> rows) {
            AtomicInteger index = new AtomicInteger(-1);
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> {
                        if ("next".equals(method.getName())) {
                            return index.incrementAndGet() < rows.size();
                        }
                        if ("close".equals(method.getName())) {
                            return null;
                        }
                        Object value = rows.get(index.get()).get(arguments[0]);
                        return switch (method.getName()) {
                            case "getString" -> value == null ? null : value.toString();
                            case "getLong" -> ((Number) value).longValue();
                            case "getInt" -> ((Number) value).intValue();
                            case "getTimestamp", "getObject" -> value;
                            default -> defaultValue(method.getReturnType());
                        };
                    });
        }

        private static Map<Object, Object> row(Object... values) {
            Map<Object, Object> row = new LinkedHashMap<>();
            for (int index = 0; index < values.length; index += 2) {
                row.put(values[index], values[index + 1]);
            }
            return row;
        }

        private static Object defaultValue(Class<?> type) {
            if (!type.isPrimitive()) return null;
            if (type == boolean.class) return false;
            if (type == int.class) return 0;
            if (type == long.class) return 0L;
            if (type == double.class) return 0D;
            if (type == float.class) return 0F;
            if (type == short.class) return (short) 0;
            if (type == byte.class) return (byte) 0;
            if (type == char.class) return '\0';
            return null;
        }
    }
}
