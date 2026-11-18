package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.commerce.CommerceRuntimeException;
import com.elmpay.payment.commerce.CommerceService;
import com.elmpay.payment.commerce.JdbcCommerceService;
import com.elmpay.payment.commerce.JdbcProviderEvidenceReplayGuard;
import com.elmpay.provider.ProviderEvidenceReceipt;
import com.elmpay.provider.ProviderEvidenceVerifier;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Real PostgreSQL sealing and recovery; local signed result fixtures are not channel acceptance. */
final class BillingUsagePostgresIT {
    private static final Instant START = Instant.now().minus(Duration.ofDays(3));
    private static final Instant END = START.plusSeconds(60);
    private static final String SUFFIX = UUID.randomUUID().toString().replace("-","");
    private static final String SCHEMA = "p1_usage_" + SUFFIX;
    private static final String ROLE = "p1_usage_role_" + SUFFIX;
    private static final String WORKER = "p1_usage_worker_" + SUFFIX;
    private static DataSource database;
    private static KeyPair signingKey;
    private static ProviderEvidenceVerifier verifier;
    private static String url;

    @BeforeAll
    static void provision() throws Exception {
        url = LoopbackPostgresTestCluster.jdbcUrl();
        assertTrue(url != null && url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/elmpay_p1_[a-z0-9_]+"));
        assertEquals("elmpay_p1_admin",LoopbackPostgresTestCluster.adminUser());
        Path repo = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (repo != null && !Files.isRegularFile(repo.resolve("governance/project-config.json"))) {
            repo = repo.getParent();
        }
        assertTrue(repo != null);
        try (Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
                Statement sql = connection.createStatement()) {
            sql.execute("CREATE SCHEMA " + SCHEMA);
            sql.execute("SET search_path TO " + SCHEMA + ",public");
            for (String file : new String[] {
                    "apps/edge-gateway/src/main/resources/db/migration/V032__payment_runtime.sql",
                    "services/payment-core/src/main/resources/db/migration/V034__durable_refund_runtime.sql",
                    "services/worker-scheduler/src/main/resources/db/migration/V012__event_delivery_runtime.sql",
                    "services/worker-scheduler/src/main/resources/db/migration/V012_1__event_envelope_revision.sql",
                    "services/payment-core/src/main/resources/db/migration/V066__durable_commerce_runtime.sql",
                    "services/payment-core/src/main/resources/db/migration/V066_1__provider_evidence_receipts.sql",
                    "services/payment-core/src/main/resources/db/migration/V109__billing_usage_watermarks.sql",
                    "services/payment-core/src/main/resources/db/migration/V109_1__usage_acceptance_order.sql",
                    "services/ledger-service/src/main/resources/db/migration/V072__immutable_ledger.sql",
                    "services/ledger-service/src/main/resources/db/migration/V073__event_ledger_posting_policy.sql"}) {
                for (String command : SqlScripts.split(Files.readString(repo.resolve(file)))) {
                    sql.execute(command);
                }
            }
            sql.execute("CREATE ROLE " + ROLE + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("GRANT USAGE ON SCHEMA " + SCHEMA + " TO " + ROLE);
            sql.execute("GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA " + SCHEMA + " TO " + ROLE);
            sql.execute("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA " + SCHEMA + " TO " + ROLE);
            sql.execute("CREATE ROLE " + WORKER + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            sql.execute("GRANT USAGE ON SCHEMA " + SCHEMA + " TO " + WORKER);
            sql.execute("GRANT SELECT,UPDATE ON billing_subscription TO " + WORKER);
            sql.execute("GRANT SELECT ON billing_plan TO " + WORKER);
            sql.execute("GRANT SELECT,INSERT ON subscription_billing_cycle TO " + WORKER);
            sql.execute("GRANT SELECT,INSERT,UPDATE ON event_aggregate_revision,outbox_event TO " + WORKER);
            sql.execute("GRANT USAGE ON SEQUENCE outbox_event_sequence_no_seq TO " + WORKER);
        }
        database = new RealDatabase();
        try (Connection connection = database.getConnection(); Statement sql = connection.createStatement()) {
            assertEquals("false",scalar(sql,"SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname=current_user"));
        }
        signingKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new ProviderEvidenceVerifier(Map.of("local-usage-test",
                new ProviderEvidenceVerifier.TrustKey(signingKey.getPublic(),"local-fixture-not-a-provider","stripe",
                        Set.of("PROVIDER_RENEWAL_RESULT","PROVIDER_DUNNING_RESULT"),
                        START.minusSeconds(60),START.plus(Duration.ofDays(30)),false)),
                new JdbcProviderEvidenceReplayGuard(database),Duration.ofMinutes(5),Duration.ZERO);
        System.out.println("usage_jvm_pid=" + ProcessHandle.current().pid() + " schema=" + SCHEMA
                + " provider_calls=0 channel_acceptance=NOT_RUN");
    }

    @Test
    void sealIsDurableAndSuccessfulResultPreservesPostSealArrivals() throws Exception {
        Fixture value = fixture(100);
        usage(value,5,"before",START);
        long version = service(END).getSubscription(value.context(),value.id()).version();
        var cycle = enqueue(value);
        assertEquals(500,cycle.amountMinor());
        assertEquals(0,pending(value));
        assertEquals(version+1,service(END).getSubscription(value.context(),value.id()).version());
        assertEquals("5:" + version + ":false",cycleSeal(value,cycle.id()));
        usage(value,2,"after",END);
        renewal(value,cycle.id(),CommerceService.RenewalOutcome.SUCCEEDED,END);
        assertEquals(2,pending(value));
        assertEquals(END.plusSeconds(60),service(END).getSubscription(value.context(),value.id()).periodEnd());
        assertEquals("5:" + version + ":false",cycleSeal(value,cycle.id()));
        assertConservation(value,7);
        proof(value);
    }

    @Test
    void sameTimestampLateArrivalAndDuplicateUsageBelongToNextPendingBucket() throws Exception {
        Fixture value = fixture(100);
        usage(value,3,"before",START);
        var cycle = enqueue(value);
        usage(value,2,"late_same_timestamp",END);
        usage(value,2,"late_same_timestamp",END);
        assertThrows(CommerceRuntimeException.class, () -> usage(value,9,"late_same_timestamp",END));
        renewal(value,cycle.id(),CommerceService.RenewalOutcome.SUCCEEDED,END);
        usage(value,3,"before",END.plusSeconds(1));
        assertEquals(2,pending(value));
        assertEquals("2",query(value,"SELECT count(*) FROM subscription_usage_inbox"));
        assertConservation(value,5);
        proof(value);
    }

    @Test
    void failedRenewalThenActualDunningRecoveryDoesNotClearNewUsage() throws Exception {
        Fixture value = fixture(100);
        usage(value,5,"before",START);
        var cycle = enqueue(value);
        usage(value,3,"after",END);
        renewal(value,cycle.id(),CommerceService.RenewalOutcome.FAILED,END);
        Instant due = END.plus(Duration.ofDays(1));
        var dunning = service(due).enqueueDueDunning(value.context().tenantId(),due,"usage-worker").orElseThrow();
        String digest = "e".repeat(64);
        service(due).recordDunningOutcome(value.context(),dunning.id(),CommerceService.RenewalOutcome.SUCCEEDED,
                digest,receipt(value,dunning.id(),"PROVIDER_DUNNING_RESULT","succeeded",digest,
                        Integer.toString(dunning.attempts()),due),"dunning-recovered","usage-test");
        assertEquals(3,pending(value));
        assertEquals("recovered",query(value,"SELECT state FROM dunning_case"));
        assertEquals(END.plusSeconds(60),service(due).getSubscription(value.context(),value.id()).periodEnd());
        assertConservation(value,8);
        proof(value);
    }

    @Test
    void zeroUsageClosesLocallyWithoutExternalDebitReceiptOrLedgerPosting() throws Exception {
        Fixture value = fixture(100);
        DataSource workerDatabase = new RealDatabase(WORKER);
        try (Connection connection = workerDatabase.getConnection(); Statement sql = connection.createStatement()) {
            assertEquals("false",scalar(sql,"SELECT has_table_privilege(current_user,'subscription_billing_cycle','UPDATE')::text"));
            assertEquals("true",scalar(sql,"SELECT has_table_privilege(current_user,'subscription_billing_cycle','INSERT')::text"));
            assertEquals("false",scalar(sql,"SELECT (rolsuper OR rolbypassrls)::text FROM pg_roles WHERE rolname=current_user"));
        }
        var worker = new JdbcCommerceService(workerDatabase,Clock.fixed(END,ZoneOffset.UTC),verifier);
        var cycle = worker.enqueueDueRenewal(value.context().tenantId(),END,"usage-worker").orElseThrow();
        assertEquals(0,cycle.amountMinor());
        assertEquals("succeeded",cycle.state());
        assertEquals("0",query(value,"SELECT count(*) FROM outbox_event WHERE event_type='billing.subscription.renewal_due.v1'"));
        assertEquals("0",query(value,"SELECT count(*) FROM subscription_billing_cycle WHERE provider_result_digest IS NOT NULL"));
        assertEquals(END.plusSeconds(60),service(END).getSubscription(value.context(),value.id()).periodEnd());
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(),END,"usage-worker").isEmpty());
        assertEquals("1",query(value,"SELECT count(*) FROM subscription_billing_cycle"));
        assertEquals("zero_amount",query(value,"SELECT payload::jsonb->>'settlement_source' FROM outbox_event WHERE aggregate_id='" + cycle.id() + "'"));
        consumeZeroResultWithRealLedger(value,cycle.id());
        assertEquals("0",query(value,"SELECT count(*) FROM ledger_transaction"));
        assertEquals("0",query(value,"SELECT count(*) FROM provider_evidence_nonce"));
        proof(value);
    }

    @Test
    void freeMeteredPlanStillSealsQuantityWithoutPretendingAProviderPaid() throws Exception {
        Fixture value = fixture(0);
        usage(value,4,"free_usage",START);
        var cycle = enqueue(value);
        assertEquals("succeeded",cycle.state());
        assertEquals(0,cycle.amountMinor());
        assertEquals(0,pending(value));
        assertEquals("4",query(value,"SELECT captured_usage_quantity::text FROM subscription_billing_cycle"));
        assertEquals("0",query(value,"SELECT count(*) FROM outbox_event WHERE event_type='billing.subscription.renewal_due.v1'"));
        assertConservation(value,4);
        proof(value);
    }

    @Test
    void concurrentUsageAndSealConserveEveryAcceptedUnit() throws Exception {
        Fixture value = fixture(100);
        usage(value,5,"before",START);
        CountDownLatch start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var add = pool.submit(() -> { await(start); return retry(() -> { usage(value,2,"racing",END);return true; }); });
            var seal = pool.submit(() -> { await(start); return retry(() ->
                    service(END).enqueueDueRenewal(value.context().tenantId(),END,"usage-worker")); });
            start.countDown();
            add.get(20,TimeUnit.SECONDS);
            // SKIP LOCKED may deliberately yield while the writer owns this row.
            // One follow-up after both owned operations finish must seal it.
            if (seal.get(20,TimeUnit.SECONDS).isEmpty()) enqueue(value);
        }
        assertEquals("1",query(value,"SELECT count(*) FROM subscription_billing_cycle"));
        assertConservation(value,7);
        assertEquals("0",query(value,"SELECT count(*) FROM subscription_billing_cycle WHERE captured_usage_quantity IS NULL"));
        proof(value);
    }

    @Test
    void arithmeticOverflowRollsBackWithoutLosingInboxOrPendingUnits() throws Exception {
        Fixture priced = fixture(Long.MAX_VALUE);
        usage(priced,2,"huge_amount",START);
        CommerceRuntimeException overflow = assertThrows(CommerceRuntimeException.class, () -> enqueue(priced));
        assertTrue(overflow.getCause() instanceof ArithmeticException);
        assertEquals(2,pending(priced));
        assertEquals("0",query(priced,"SELECT count(*) FROM subscription_billing_cycle"));
        Fixture counted = fixture(1);
        usage(counted,Long.MAX_VALUE,"max_quantity",START);
        assertThrows(CommerceRuntimeException.class, () -> usage(counted,1,"overflow_quantity",START));
        assertEquals(Long.MAX_VALUE,pending(counted));
        assertEquals("1",query(counted,"SELECT count(*) FROM subscription_usage_inbox"));
        proof(priced);
        proof(counted);
    }

    @Test
    void legacyVerifiedMoneyFactIsRetainedForReconciliationWithoutAdvancingOrRedebiting() throws Exception {
        Fixture value = fixture(100);
        usage(value,7,"legacy_pending",START);
        UUID cycle = insertLegacyCycle(value);
        renewal(value,cycle,CommerceService.RenewalOutcome.SUCCEEDED,END);
        assertEquals("succeeded:true:true",query(value,"SELECT state||':'||usage_reconciliation_required||':'||"
                + "(provider_result_digest IS NOT NULL) FROM subscription_billing_cycle"));
        assertEquals(7,pending(value));
        assertEquals(END,service(END).getSubscription(value.context(),value.id()).periodEnd());
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(),END,"usage-worker").isEmpty());
        Fixture failed = fixture(100);
        usage(failed,4,"legacy_unresolved",START);
        UUID failedCycle = insertLegacyCycle(failed);
        renewal(failed,failedCycle,CommerceService.RenewalOutcome.FAILED,END);
        Instant due = END.plus(Duration.ofDays(1));
        assertTrue(service(due).enqueueDueDunning(failed.context().tenantId(),due,"usage-worker").isEmpty());
        assertEquals(4,pending(failed));
        UUID inFlight;
        try (Connection connection = tenant(failed); PreparedStatement sql = connection.prepareStatement(
                "UPDATE dunning_case SET state='waiting_provider_query',attempts=1,next_attempt_at=NULL RETURNING id")) {
            try (ResultSet rows = sql.executeQuery()) { assertTrue(rows.next());inFlight=rows.getObject(1,UUID.class); }
            connection.commit();
        }
        String digest = "e".repeat(64);
        service(due).recordDunningOutcome(failed.context(),inFlight,CommerceService.RenewalOutcome.SUCCEEDED,digest,
                receipt(failed,inFlight,"PROVIDER_DUNNING_RESULT","succeeded",digest,"1",due),"legacy-inflight","usage-test");
        assertEquals("recovered",query(failed,"SELECT state FROM dunning_case"));
        assertEquals(4,pending(failed));
        assertEquals(END,service(due).getSubscription(failed.context(),failed.id()).periodEnd());
        assertEquals("1",query(failed,"SELECT count(*) FROM outbox_event WHERE event_type='billing.dunning.result.v1' "
                + "AND payload::jsonb->>'result'='succeeded' AND payload::jsonb->>'verification_receipt_digest' IS NOT NULL"));
        proof(value);
        proof(failed);
    }

    @Test
    void tenantProjectAndInvalidQuantityCannotMutateASealOrUsageInbox() throws Exception {
        Fixture value = fixture(100);
        var otherProject = new CommerceService.Context(value.context().tenantId(),UUID.randomUUID(),"other-project");
        var otherTenant = new CommerceService.Context(UUID.randomUUID(),value.context().projectId(),"other-tenant");
        assertThrows(CommerceRuntimeException.class, () -> service(START).recordUsage(otherProject,value.id(),1,"wrong_project","usage-test"));
        assertThrows(CommerceRuntimeException.class, () -> service(START).recordUsage(otherTenant,value.id(),1,"wrong_tenant","usage-test"));
        assertThrows(CommerceRuntimeException.class, () -> usage(value,0,"zero_quantity",START));
        assertEquals(0,pending(value));
        assertEquals("0",query(value,"SELECT count(*) FROM subscription_usage_inbox"));
        usage(value,1,"valid",START);
        var cycle = enqueue(value);
        assertThrows(CommerceRuntimeException.class, () -> service(END).recordRenewalOutcome(otherProject,
                cycle.id(),CommerceService.RenewalOutcome.SUCCEEDED,"a".repeat(64),
                receipt(value,cycle.id(),"PROVIDER_RENEWAL_RESULT","succeeded","a".repeat(64),null,END),"wrong_result","usage-test"));
        assertEquals("queued",query(value,"SELECT state FROM subscription_billing_cycle"));
        assertConservation(value,1);
        proof(value);
    }

    @Test
    void outboxFailureRollsBackCycleAndPendingClearInSameTransaction() throws Exception {
        Fixture value = fixture(100);
        usage(value,5,"before",START);
        long version = service(END).getSubscription(value.context(),value.id()).version();
        String constraint = "usage_outbox_failure_" + UUID.randomUUID().toString().replace("-","");
        try (Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
                Statement sql = connection.createStatement()) {
            sql.execute("ALTER TABLE " + SCHEMA + ".outbox_event ADD CONSTRAINT " + constraint
                    + " CHECK(tenant_id<>'" + value.context().tenantId() + "' OR event_type<>'billing.subscription.renewal_due.v1')");
        }
        CommerceRuntimeException failure = assertThrows(CommerceRuntimeException.class, () -> enqueue(value));
        assertTrue(failure.getCause().getMessage().contains(constraint));
        assertEquals(5,pending(value));
        assertEquals(version,service(END).getSubscription(value.context(),value.id()).version());
        assertEquals("0",query(value,"SELECT count(*) FROM subscription_billing_cycle"));
        assertEquals("1",query(value,"SELECT count(*) FROM subscription_usage_inbox"));
        proof(value);
    }

    private static Fixture fixture(long amount) {
        var context = new CommerceService.Context(UUID.randomUUID(),UUID.randomUUID(),"usage-operator");
        var service = service(START);
        var plan = service.createPlan(context,new CommerceService.PlanCommand("metered",amount,"USD",60,0,true,1),"plan","usage-test");
        var mandate = service.createMandate(context,new CommerceService.MandateCommand("test-customer","stripe", "test-mandate",
                "psp://stripe/test","renewal",Long.MAX_VALUE,"USD","d".repeat(64)),"mandate","usage-test");
        return new Fixture(context,service.createSubscription(context,new CommerceService.SubscriptionCommand(
                "test-customer",plan.id(),mandate.id()),"subscribe","usage-test").id());
    }

    private static JdbcCommerceService service(Instant at) {
        return new JdbcCommerceService(database,Clock.fixed(at,ZoneOffset.UTC),verifier);
    }

    private static void usage(Fixture value,long quantity,String key,Instant at) {
        service(at).recordUsage(value.context(),value.id(),quantity,key,"usage-test");
    }

    private static CommerceService.BillingCycle enqueue(Fixture value) {
        return service(END).enqueueDueRenewal(value.context().tenantId(),END,"usage-worker").orElseThrow();
    }

    private static void renewal(Fixture value,UUID cycle,CommerceService.RenewalOutcome outcome,Instant at) throws Exception {
        String digest = "a".repeat(64);
        service(at).recordRenewalOutcome(value.context(),cycle,outcome,digest,
                receipt(value,cycle,"PROVIDER_RENEWAL_RESULT",outcome.name().toLowerCase(java.util.Locale.ROOT),digest,null,at),
                "renewal_" + outcome.name(),"usage-test");
    }

    private static ProviderEvidenceReceipt receipt(Fixture value,UUID entity,String type,String outcome,
            String digest,String attempt,Instant at) throws Exception {
        Map<String,String> fields = new LinkedHashMap<>(Map.of("tenantId",value.context().tenantId().toString(),
                "projectId",value.context().projectId().toString(),"provider","stripe","entityId",entity.toString(),
                "subscriptionId",value.id().toString(),"result",outcome,"providerResultDigest",digest));
        fields.put(type.equals("PROVIDER_RENEWAL_RESULT") ? "billingCycleId" : "dunningCaseId",entity.toString());
        if (attempt != null) fields.put("attempt",attempt);
        var unsigned = new ProviderEvidenceReceipt(type,fields,"local-usage-test",at.minusSeconds(1),
                at.plusSeconds(120),UUID.randomUUID().toString(),new byte[64]);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(signingKey.getPrivate());
        signer.update(ProviderEvidenceVerifier.signaturePayload(unsigned));
        return new ProviderEvidenceReceipt(type,fields,unsigned.keyId(),unsigned.issuedAt(),unsigned.expiresAt(),unsigned.nonce(),signer.sign());
    }

    private static UUID insertLegacyCycle(Fixture value) throws SQLException {
        UUID id = UUID.randomUUID();
        try (Connection connection = tenant(value); PreparedStatement sql = connection.prepareStatement("""
                INSERT INTO subscription_billing_cycle
                (id,tenant_id,project_id,subscription_id,period_start,period_end,amount_minor,currency,state,created_at,updated_at)
                VALUES (?,?,?,?,?, ?,500,'USD','queued',?,?)
                """)) {
            sql.setObject(1,id);sql.setObject(2,value.context().tenantId());sql.setObject(3,value.context().projectId());
            sql.setObject(4,value.id());sql.setTimestamp(5,java.sql.Timestamp.from(START));
            sql.setTimestamp(6,java.sql.Timestamp.from(END));sql.setTimestamp(7,java.sql.Timestamp.from(END));
            sql.setTimestamp(8,java.sql.Timestamp.from(END));sql.executeUpdate();connection.commit();
        }
        return id;
    }

    private static Connection tenant(Fixture value) throws SQLException {
        Connection connection = database.getConnection();connection.setAutoCommit(false);
        try (PreparedStatement sql = connection.prepareStatement("SELECT set_config('app.tenant_id',?,true)")) {
            sql.setString(1,value.context().tenantId().toString());sql.execute();
        }
        return connection;
    }

    private static String query(Fixture value,String query) throws SQLException {
        try (Connection connection = tenant(value); Statement sql = connection.createStatement()) {
            return scalar(sql,query);
        }
    }

    private static String scalar(Statement sql,String query) throws SQLException {
        try (ResultSet rows = sql.executeQuery(query)) { assertTrue(rows.next());return rows.getString(1); }
    }

    private static long pending(Fixture value) { return service(END).getSubscription(value.context(),value.id()).usageQuantity(); }

    private static String cycleSeal(Fixture value,UUID id) throws SQLException {
        return query(value,"SELECT captured_usage_quantity||':'||usage_watermark_version||':'||usage_reconciliation_required "
                + "FROM subscription_billing_cycle WHERE id='" + id + "'");
    }

    private static void assertConservation(Fixture value,long accepted) throws SQLException {
        assertEquals(Long.toString(accepted),query(value,"SELECT coalesce(sum(captured_usage_quantity),0)+"
                + "(SELECT usage_quantity FROM billing_subscription WHERE id='" + value.id() + "') FROM subscription_billing_cycle"));
        assertEquals(Long.toString(accepted),query(value,"SELECT sum(quantity)::text FROM subscription_usage_inbox"));
        assertEquals("0",query(value,"SELECT count(*) FROM subscription_usage_inbox WHERE accepted_subscription_version IS NULL"));
        assertEquals("0",query(value,"""
                SELECT count(*) FROM subscription_billing_cycle c
                 WHERE c.subscription_id='%s'
                   AND c.captured_usage_quantity IS NOT NULL
                   AND c.captured_usage_quantity <> (
                       SELECT coalesce(sum(u.quantity),0)
                         FROM subscription_usage_inbox u
                        WHERE u.subscription_id=c.subscription_id
                          AND u.accepted_subscription_version <= c.usage_watermark_version
                   )
                """.formatted(value.id())));
    }

    private static void proof(Fixture value) throws Exception {
        String image = query(value,"SELECT row_to_json(s)::text FROM billing_subscription s WHERE id='" + value.id() + "'");
        System.out.println("usage_postimage subscription=" + value.id() + " sha256=" + HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(image.getBytes(StandardCharsets.UTF_8))));
    }

    private static void consumeZeroResultWithRealLedger(Fixture value,UUID cycle) throws Exception {
        Class<?> delivery = Class.forName("com.elmpay.scheduler.events.JdbcEventDeliveryStore");
        Class<?> ledger = Class.forName("com.elmpay.ledger.LedgerService");
        Class<?> resolver = Class.forName("com.elmpay.scheduler.LedgerPostingConsumer$PostingPolicyResolver");
        Class<?> message = Class.forName("com.elmpay.scheduler.events.JdbcEventDeliveryStore$InboxMessage");
        Class<?> consumerType = Class.forName("com.elmpay.scheduler.LedgerPostingConsumer");
        Object consumer = consumerType.getConstructor(delivery,ledger,resolver,Duration.class,Duration.class).newInstance(
                delivery.getConstructor(DataSource.class).newInstance(database),
                ledger.getConstructor(DataSource.class,Clock.class).newInstance(database,Clock.fixed(END,ZoneOffset.UTC)),
                Class.forName("com.elmpay.scheduler.JdbcPostingPolicyResolver").getConstructor().newInstance(),
                Duration.ofSeconds(30),Duration.ofSeconds(1));
        var constructor = message.getConstructor(UUID.class,UUID.class,UUID.class,String.class,UUID.class,long.class,
                String.class,int.class,String.class,Instant.class,Instant.class,String.class);
        int applied = 0;
        try (Connection connection = tenant(value); PreparedStatement query = connection.prepareStatement(
                "SELECT * FROM outbox_event WHERE aggregate_id=? ORDER BY aggregate_revision")) {
            query.setObject(1,cycle);
            try (ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    Object event = constructor.newInstance(rows.getObject("id",UUID.class),value.context().tenantId(),
                            value.context().projectId(),rows.getString("aggregate_type"),cycle,rows.getLong("aggregate_revision"),
                            rows.getString("event_type"),rows.getInt("event_version"),rows.getString("payload"),
                            rows.getTimestamp("occurred_at").toInstant(),rows.getTimestamp("recorded_at").toInstant(),rows.getString("trace_id"));
                    var consume = consumerType.getMethod("consume",message,String.class,Instant.class);
                    assertEquals("APPLIED",consume.invoke(consumer,event,"usage-ledger",END).toString());
                    assertEquals("DUPLICATE",consume.invoke(consumer,event,"usage-ledger",END).toString());
                    applied++;
                }
            }
        }
        assertEquals(1,applied);
        assertEquals("1",query(value,"SELECT count(*) FROM ledger_event_revision_guard WHERE aggregate_id='" + cycle + "'"));
    }

    private static void await(CountDownLatch latch) {
        try { assertTrue(latch.await(10,TimeUnit.SECONDS)); }
        catch (InterruptedException failure) { Thread.currentThread().interrupt();throw new IllegalStateException(failure); }
    }

    private static <T> T retry(java.util.function.Supplier<T> action) {
        for (int count=0;count<4;count++) {
            try { return action.get(); }
            catch (CommerceRuntimeException failure) {
                if (count==3 || !(failure.getCause() instanceof SQLException sql)
                        || !("40001".equals(sql.getSQLState()) || "40P01".equals(sql.getSQLState()))) throw failure;
            }
        }
        throw new AssertionError("bounded serialization retries exhausted");
    }

    private record Fixture(CommerceService.Context context,UUID id) { }

    private static final class RealDatabase implements DataSource {
        private final String role;
        private RealDatabase() { this(ROLE); }
        private RealDatabase(String role) { this.role=role; }
        @Override public Connection getConnection() throws SQLException {
            Connection connection = DriverManager.getConnection(url,"elmpay_p1_admin","");
            try (Statement sql = connection.createStatement()) {
                sql.execute("SET ROLE " + role);sql.execute("SET search_path TO " + SCHEMA + ",public");
                return connection;
            } catch (SQLException failure) { connection.close();throw failure; }
        }
        @Override public Connection getConnection(String user,String password) throws SQLException { throw new SQLException("task-owned role only"); }
        @Override public PrintWriter getLogWriter() { return DriverManager.getLogWriter(); }
        @Override public void setLogWriter(PrintWriter writer) { DriverManager.setLogWriter(writer); }
        @Override public void setLoginTimeout(int seconds) { DriverManager.setLoginTimeout(seconds); }
        @Override public int getLoginTimeout() { return DriverManager.getLoginTimeout(); }
        @Override public Logger getParentLogger() { return Logger.getLogger("java.sql"); }
        @Override public <T> T unwrap(Class<T> type) throws SQLException { if(type.isInstance(this)) return type.cast(this);throw new SQLException("not wrapped"); }
        @Override public boolean isWrapperFor(Class<?> type) { return type.isInstance(this); }
    }
}
