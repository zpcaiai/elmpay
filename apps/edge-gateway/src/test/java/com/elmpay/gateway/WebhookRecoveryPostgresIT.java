package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Real repository classes, PostgreSQL transactions and FORCE RLS; no network/provider acceptance. */
final class WebhookRecoveryPostgresIT {
    private static final Instant NOW = Instant.now().minusSeconds(60);
    private static final String SUFFIX = UUID.randomUUID().toString().replace("-", "");
    private static final String SCHEMA = "p1_recovery_" + SUFFIX;
    private static final String ADMIN = "p1_recovery_admin_" + SUFFIX;
    private static final String WORKER = "p1_recovery_worker_" + SUFFIX;
    private static String url;
    private static Path repo;

    @BeforeAll
    static void provision() throws Exception {
        url = LoopbackPostgresTestCluster.jdbcUrl();
        assertTrue(url != null && url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/elmpay_p1_[a-z0-9_]+"));
        assertEquals("elmpay_p1_admin", LoopbackPostgresTestCluster.adminUser());
        repo = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (repo != null && !Files.isRegularFile(repo.resolve("governance/project-config.json"))) {
            repo = repo.getParent();
        }
        assertTrue(repo != null);
        try (Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
                Statement sql = connection.createStatement()) {
            sql.execute("CREATE SCHEMA " + SCHEMA);
            sql.execute("SET search_path TO " + SCHEMA + ",public");
            for (String name : new String[] {"V038__business_webhook_delivery.sql", "V108__webhook_recovery_rounds.sql"}) {
                for (String command : SqlScripts.split(Files.readString(repo.resolve(
                        "services/webhook-delivery/src/main/resources/db/migration/" + name)))) {
                    sql.execute(command);
                }
            }
            sql.execute("CREATE ROLE " + ADMIN + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("CREATE ROLE " + WORKER + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("GRANT USAGE ON SCHEMA " + SCHEMA + " TO " + ADMIN + "," + WORKER);
            sql.execute("GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA " + SCHEMA + " TO " + ADMIN);
            sql.execute("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA " + SCHEMA + " TO " + ADMIN);
            sql.execute("GRANT SELECT ON webhook_endpoint TO " + WORKER);
            sql.execute("GRANT SELECT,UPDATE ON webhook_delivery_outbox TO " + WORKER);
            sql.execute("GRANT INSERT ON webhook_delivery_dead_letter TO " + WORKER);
        }
        try (Connection connection = new RealDatabase(ADMIN).getConnection(); Statement sql = connection.createStatement()) {
            assertEquals("false", scalar(sql,"SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname=current_user"));
        }
        System.out.println("webhook_recovery_jvm_pid=" + ProcessHandle.current().pid()
                + " schema=" + SCHEMA + " external_calls=0 channel_acceptance=NOT_RUN");
    }

    @Test
    void twoFailuresAndReplaysRetainBothRoundsAndMonotonicFences() throws Exception {
        Fixture value = fixture();
        Object first = claim(value, NOW);
        dead(value, first, "first_error", NOW);
        replay(value,"ticket_one",NOW);
        Object second = claim(value,NOW.plusSeconds(1));
        assertTrue(number(second,"fencingToken") > number(first,"fencingToken"));
        assertEquals(0, number(second,"attemptCount"));
        dead(value,second,"second_error",NOW.plusSeconds(2));
        assertEquals("2", query(value,"SELECT count(*) FROM webhook_delivery_dead_letter"));
        assertEquals("first_error,second_error", query(value,
                "SELECT string_agg(final_error_code,',' ORDER BY recovery_round) FROM webhook_delivery_dead_letter"));
        assertEquals("1,1", query(value,"SELECT string_agg(attempt_count::text,',' ORDER BY recovery_round) FROM webhook_delivery_dead_letter"));
        replay(value,"ticket_two",NOW.plusSeconds(3));
        Object third = claim(value,NOW.plusSeconds(4));
        call(value.repository(),"markDelivered",third,200,NOW.plusSeconds(4));
        assertEquals("DELIVERED:3:1", state(value));
        assertEquals("2", query(value,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        assertEquals("2", query(value,"SELECT count(*) FROM webhook_delivery_dead_letter WHERE replayed_at IS NOT NULL"));
        assertEquals("1",query(value,"SELECT count(DISTINCT encode(payload,'hex')) FROM webhook_delivery_dead_letter"));
        proof(value);
    }

    @Test
    void duplicateTicketNeverReplaysALaterRoundAndBindsApprovalFields() throws Exception {
        Fixture value = fixture();
        dead(value,claim(value,NOW),"first",NOW);
        replay(value,"original_ticket",NOW);
        replay(value,"original_ticket",NOW.plusSeconds(1));
        Object second = claim(value,NOW.plusSeconds(2));
        replay(value,"original_ticket",NOW.plusSeconds(3));
        assertEquals("IN_FLIGHT:2:0",state(value));
        dead(value,second,"second",NOW.plusSeconds(4));
        replay(value,"original_ticket",NOW.plusSeconds(5));
        assertEquals("DEAD:2:1",state(value));
        assertThrows(IllegalArgumentException.class, () -> call(value.repository(),"replayDeadLetter",
                value.tenant(),value.id(),"actor_changed","approver_one","reason","original_ticket",NOW));
        assertThrows(IllegalArgumentException.class, () -> call(value.repository(),"replayDeadLetter",
                value.tenant(),value.id(),"actor_one","approver_changed","reason","original_ticket",NOW));
        assertThrows(IllegalArgumentException.class, () -> call(value.repository(),"replayDeadLetter",
                value.tenant(),value.id(),"actor_one","approver_one","different_reason","original_ticket",NOW));
        replay(value,"next_ticket",NOW.plusSeconds(6));
        assertEquals("PENDING:3:0",state(value));
        assertEquals("2",query(value,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        proof(value);
    }

    @Test
    void staleLeaseCannotCopyHistoryOrChangeStateAcrossRecovery() throws Exception {
        Fixture value = fixture();
        Object stale = claim(value,NOW);
        Object current = claim(value,NOW.plusSeconds(31));
        assertThrows(IllegalStateException.class, () -> dead(value,stale,"stale",NOW.plusSeconds(31)));
        assertEquals("IN_FLIGHT:1:0",state(value));
        assertEquals("0",query(value,"SELECT count(*) FROM webhook_delivery_dead_letter"));
        dead(value,current,"current",NOW.plusSeconds(32));
        replay(value,"recover_ticket",NOW.plusSeconds(33));
        assertThrows(IllegalStateException.class, () -> dead(value,current,"old_round",NOW.plusSeconds(34)));
        assertEquals("PENDING:2:0",state(value));
        assertEquals("1",query(value,"SELECT count(*) FROM webhook_delivery_dead_letter"));
        proof(value);
    }

    @Test
    void concurrentSameTicketIsOneReplayAndDistinctTicketsCannotDoubleReplay() throws Exception {
        Fixture same = fixture();
        dead(same,claim(same,NOW),"failure",NOW);
        assertEquals(2,race(same,"same_ticket","same_ticket"));
        assertEquals("PENDING:2:0",state(same));
        assertEquals("1",query(same,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        Fixture distinct = fixture();
        dead(distinct,claim(distinct,NOW),"failure",NOW);
        assertEquals(1,race(distinct,"ticket_left","ticket_right"));
        assertEquals("PENDING:2:0",state(distinct));
        assertEquals("1",query(distinct,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        proof(same);
        proof(distinct);
    }

    @Test
    void auditInsertionFailureRollsBackHistoryAndOutboxTogether() throws Exception {
        Fixture value = fixture();
        dead(value,claim(value,NOW),"failure",NOW);
        try (Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
                Statement sql = connection.createStatement()) {
            sql.execute("ALTER TABLE " + SCHEMA + ".webhook_delivery_admin_audit ADD CONSTRAINT audit_failure_probe "
                    + "CHECK(reason <> 'reject_audit')");
        }
        IllegalStateException auditFailure = assertThrows(IllegalStateException.class, () -> call(value.repository(),"replayDeadLetter",value.tenant(),
                value.id(),"actor_one","approver_one","reject_audit","rollback_ticket",NOW));
        assertTrue(auditFailure.getCause().getMessage().contains("audit_failure_probe"));
        assertEquals("DEAD:1:1",state(value));
        assertEquals("1",query(value,"SELECT count(*) FROM webhook_delivery_dead_letter WHERE replayed_at IS NULL"));
        assertEquals("0",query(value,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        replay(value,"rollback_ticket",NOW.plusSeconds(1));
        assertEquals("PENDING:2:0",state(value));
        proof(value);
    }

    @Test
    void tenantIsolationAndDualApprovalAreNotBypassed() throws Exception {
        Fixture value = fixture();
        dead(value,claim(value,NOW),"failure",NOW);
        assertThrows(IllegalArgumentException.class, () -> call(value.repository(),"replayDeadLetter","other_tenant",
                value.id(),"actor_one","approver_one","reason","tenant_ticket",NOW));
        assertThrows(IllegalArgumentException.class, () -> call(value.repository(),"replayDeadLetter",value.tenant(),
                value.id(),"actor_one","actor_one","reason","self_approved",NOW));
        try (Connection connection = new RealDatabase(ADMIN).getConnection(); Statement sql = connection.createStatement()) {
            connection.setAutoCommit(false);
            sql.execute("SELECT set_config('app.tenant_id','other_tenant',true)");
            assertEquals("other_tenant",scalar(sql,"SELECT current_setting('app.tenant_id')"));
            assertEquals("0",scalar(sql,"SELECT count(*) FROM webhook_delivery_dead_letter"));
            assertEquals("0",scalar(sql,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        }
        assertEquals("DEAD:1:1",state(value));
        proof(value);
    }

    @Test
    void actualWorkerNeedsOnlyInsertOnHistoryForEveryRound() throws Exception {
        Fixture value = fixture();
        Object worker = repository(new RealDatabase(WORKER));
        try (Connection connection = new RealDatabase(WORKER).getConnection(); Statement sql = connection.createStatement()) {
            assertEquals("false",scalar(sql,"SELECT has_table_privilege(current_user,'webhook_delivery_dead_letter','SELECT')::text"));
            assertFalse(Boolean.parseBoolean(scalar(sql,"SELECT has_table_privilege(current_user,'webhook_delivery_dead_letter','UPDATE')::text")));
        }
        Object first = ((Optional<?>)call(worker,"claim",value.tenant(),NOW,NOW.plusSeconds(30))).orElseThrow();
        call(worker,"deadLetter",first,503,"worker_first",NOW);
        replay(value,"worker_recover",NOW.plusSeconds(1));
        Object second = ((Optional<?>)call(worker,"claim",value.tenant(),NOW.plusSeconds(2),NOW.plusSeconds(32))).orElseThrow();
        call(worker,"deadLetter",second,504,"worker_second",NOW.plusSeconds(3));
        assertEquals("DEAD:2:1",state(value));
        assertEquals("2",query(value,"SELECT count(*) FROM webhook_delivery_dead_letter"));
        proof(value);
    }

    @Test
    void failedHistoryCopyAndMissingRoundCannotPartiallyCommit() throws Exception {
        Fixture value = fixture();
        Object delivery = claim(value,NOW);
        assertThrows(IllegalStateException.class, () -> dead(value,delivery,"x".repeat(81),NOW));
        try (Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
                Statement sql = connection.createStatement()) {
            sql.execute("ALTER TABLE " + SCHEMA + ".webhook_delivery_dead_letter ADD CONSTRAINT history_failure_probe "
                    + "CHECK(final_error_code <> 'reject_history')");
        }
        IllegalStateException historyFailure = assertThrows(IllegalStateException.class,
                () -> dead(value,delivery,"reject_history",NOW));
        assertTrue(historyFailure.getCause().getMessage().contains("history_failure_probe"));
        assertEquals("IN_FLIGHT:1:0",state(value));
        assertEquals(Long.toString(number(delivery,"fencingToken")),
                query(value,"SELECT fencing_token::text FROM webhook_delivery_outbox"));
        assertEquals("0",query(value,"SELECT count(*) FROM webhook_delivery_dead_letter"));
        dead(value,delivery,"valid_error",NOW.plusSeconds(1));
        Fixture missing = fixture();
        try (Connection connection = tenant(missing); Statement sql = connection.createStatement()) {
            sql.execute("UPDATE webhook_delivery_outbox SET state='DEAD' WHERE delivery_id=" + missing.id());
            connection.commit();
        }
        assertThrows(IllegalArgumentException.class, () -> replay(missing,"missing_round",NOW));
        assertEquals("DEAD:1:0",state(missing));
        assertEquals("0",query(missing,"SELECT count(*) FROM webhook_delivery_admin_audit"));
        proof(value);
    }

    private static int race(Fixture value,String first,String second) throws Exception {
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var threads = Executors.newFixedThreadPool(2)) {
            var left = threads.submit(() -> replayAfterBarrier(value,first,ready,start));
            var right = threads.submit(() -> replayAfterBarrier(value,second,ready,start));
            assertTrue(ready.await(10,TimeUnit.SECONDS));
            start.countDown();
            return left.get(20,TimeUnit.SECONDS) + right.get(20,TimeUnit.SECONDS);
        }
    }

    private static int replayAfterBarrier(Fixture value,String ticket,CountDownLatch ready,CountDownLatch start)
            throws Exception {
        ready.countDown();
        assertTrue(start.await(10,TimeUnit.SECONDS));
        try {
            replay(value,ticket,NOW.plusSeconds(1));
            return 1;
        } catch (IllegalArgumentException expectedConflict) {
            assertTrue(expectedConflict.getMessage() != null && !expectedConflict.getMessage().isBlank());
            return 0;
        }
    }

    private static Fixture fixture() throws Exception {
        String tenant = "tenant_" + UUID.randomUUID().toString().replace("-","");
        Object repository = repository(new RealDatabase(ADMIN));
        try (Connection connection = new RealDatabase(ADMIN).getConnection(); Statement sql = connection.createStatement()) {
            connection.setAutoCommit(false);
            sql.execute("SELECT set_config('app.tenant_id','" + tenant + "',true)");
            sql.execute("INSERT INTO webhook_endpoint VALUES ('" + tenant + "','project_one','endpoint_one',"
                    + "'https://example.com/hook','example.com','ACTIVE',2,now(),now())");
            connection.commit();
        }
        assertEquals(true,call(repository,"enqueue",tenant,"project_one","endpoint_one","event_one", "payment.succeeded",
                "{\"immutable\":true}".getBytes(StandardCharsets.UTF_8),NOW));
        Fixture placeholder = new Fixture(tenant,0,repository);
        return new Fixture(tenant,Long.parseLong(query(placeholder,"SELECT delivery_id::text FROM webhook_delivery_outbox")),repository);
    }

    private static Object repository(DataSource database) throws Exception {
        return Class.forName("com.elmpay.webhook.delivery.DataSourceWebhookOutbox")
                .getConstructor(DataSource.class).newInstance(database);
    }

    private static Object call(Object subject,String method,Object... arguments) throws Exception {
        for (var candidate : subject.getClass().getMethods()) {
            if (candidate.getName().equals(method) && candidate.getParameterCount()==arguments.length) {
                try {
                    return candidate.invoke(subject,arguments);
                } catch (InvocationTargetException failure) {
                    if (failure.getCause() instanceof Exception exception) {
                        throw exception;
                    }
                    throw failure;
                }
            }
        }
        throw new NoSuchMethodException(method);
    }

    private static long number(Object record,String method) throws Exception {
        return ((Number)call(record,method)).longValue();
    }

    private static Object claim(Fixture value,Instant at) throws Exception {
        return ((Optional<?>)call(value.repository(),"claim",value.tenant(),at,at.plusSeconds(30))).orElseThrow();
    }

    private static void dead(Fixture value,Object delivery,String error,Instant at) throws Exception {
        call(value.repository(),"deadLetter",delivery,503,error,at);
    }

    private static void replay(Fixture value,String ticket,Instant at) throws Exception {
        call(value.repository(),"replayDeadLetter",value.tenant(),value.id(),"actor_one","approver_one","reason",ticket,at);
    }

    private static Connection tenant(Fixture value) throws SQLException {
        Connection connection = new RealDatabase(ADMIN).getConnection();
        connection.setAutoCommit(false);
        try (Statement sql = connection.createStatement()) {
            sql.execute("SELECT set_config('app.tenant_id','" + value.tenant() + "',true)");
        }
        return connection;
    }

    private static String query(Fixture value,String query) throws SQLException {
        try (Connection connection = tenant(value); Statement sql = connection.createStatement()) {
            return scalar(sql,query);
        }
    }

    private static String scalar(Statement sql,String query) throws SQLException {
        try (ResultSet rows = sql.executeQuery(query)) {
            assertTrue(rows.next());
            return rows.getString(1);
        }
    }

    private static String state(Fixture value) throws SQLException {
        return query(value,"SELECT state||':'||recovery_round||':'||attempt_count FROM webhook_delivery_outbox");
    }

    private static void proof(Fixture value) throws Exception {
        String rows = query(value,"SELECT coalesce(string_agg(to_jsonb(d)::text,',' ORDER BY recovery_round),'') "
                + "FROM webhook_delivery_dead_letter d");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(rows.getBytes(StandardCharsets.UTF_8)));
        System.out.println("recovery_postimage tenant=" + value.tenant() + " sha256=" + hash);
    }

    private record Fixture(String tenant,long id,Object repository) { }

    private record RealDatabase(String role) implements DataSource {
        @Override public Connection getConnection() throws SQLException {
            Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
            try (Statement sql = connection.createStatement()) {
                sql.execute("SET ROLE " + role);
                sql.execute("SET search_path TO " + SCHEMA + ",public");
            }
            return connection;
        }
        @Override public Connection getConnection(String user,String password) throws SQLException {
            throw new SQLException("task-owned role only");
        }
        @Override public PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(PrintWriter value) throws SQLException { throw new SQLException("unsupported"); }
        @Override public void setLoginTimeout(int seconds) throws SQLException { throw new SQLException("unsupported"); }
        @Override public int getLoginTimeout() { return 0; }
        @Override public Logger getParentLogger() { return Logger.getLogger("elmpay.p1.recovery"); }
        @Override public <T> T unwrap(Class<T> type) throws SQLException { throw new SQLException("not wrapped"); }
        @Override public boolean isWrapperFor(Class<?> type) { return false; }
    }
}
