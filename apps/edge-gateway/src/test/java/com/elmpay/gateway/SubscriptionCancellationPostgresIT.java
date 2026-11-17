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

/**
 * Real PostgreSQL lifecycle tests. No in-memory repository, JDBC proxy or provider simulator.
 * Signed test receipts exercise the result boundary only; they are NOT channel acceptance.
 * An explicit task-owned database is mandatory; missing setup fails instead of skipping.
 */
final class SubscriptionCancellationPostgresIT {
    private static final Instant START = Instant.now().minus(Duration.ofDays(3));
    private static final Instant END = START.plusSeconds(60);
    private static final String ROLE = "p1_cancel_" + UUID.randomUUID().toString().replace("-", "");
    private static final String SCHEMA = "p1_cancel_" + UUID.randomUUID().toString().replace("-", "");
    private static final String RENEWAL = "PROVIDER_RENEWAL_RESULT";
    private static final String DUNNING = "PROVIDER_DUNNING_RESULT";
    private static DataSource database;
    private static KeyPair signingKey;
    private static ProviderEvidenceVerifier verifier;

    @BeforeAll
    static void provisionRealDatabase() throws Exception {
        String url = LoopbackPostgresTestCluster.jdbcUrl();
        assertTrue(url != null && url.matches(
                "jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/elmpay_p1_[a-z0-9_]+"),
                "a dedicated loopback elmpay_p1_* PostgreSQL database is required");
        String user = LoopbackPostgresTestCluster.adminUser();
        assertEquals("elmpay_p1_admin", user, "only the isolated task cluster is accepted");
        Path repo = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (repo != null && !Files.isRegularFile(repo.resolve("governance/project-config.json"))) {
            repo = repo.getParent();
        }
        assertTrue(repo != null, "repository root must be discoverable");
        try (Connection connection = DriverManager.getConnection(url, user, "");
                Statement statement = connection.createStatement()) {
            statement.execute("CREATE ROLE " + ROLE + " NOLOGIN NOSUPERUSER NOBYPASSRLS");
            statement.execute("CREATE SCHEMA " + SCHEMA);
            statement.execute("SET search_path TO " + SCHEMA + ",public");
            for (String path : new String[] {
                    "apps/edge-gateway/src/main/resources/db/migration/V032__payment_runtime.sql",
                    "services/payment-core/src/main/resources/db/migration/V034__durable_refund_runtime.sql",
                    "services/worker-scheduler/src/main/resources/db/migration/V012__event_delivery_runtime.sql",
                    "services/worker-scheduler/src/main/resources/db/migration/V012_1__event_envelope_revision.sql",
                    "services/payment-core/src/main/resources/db/migration/V066__durable_commerce_runtime.sql",
                    "services/payment-core/src/main/resources/db/migration/V066_1__provider_evidence_receipts.sql",
                    "services/payment-core/src/main/resources/db/migration/V109__billing_usage_watermarks.sql"}) {
                statement.execute(Files.readString(repo.resolve(path)));
            }
            for (String path : new String[] {
                    "services/ledger-service/src/main/resources/db/migration/V072__immutable_ledger.sql",
                    "services/ledger-service/src/main/resources/db/migration/V073__event_ledger_posting_policy.sql"}) {
                statement.execute(Files.readString(repo.resolve(path)));
            }
            statement.execute("GRANT USAGE ON SCHEMA " + SCHEMA + " TO " + ROLE);
            statement.execute("GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA "
                    + SCHEMA + " TO " + ROLE);
            statement.execute("GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA "
                    + SCHEMA + " TO " + ROLE);
        }
        database = new RealPostgresDataSource(url, user);
        try (Connection connection = database.getConnection(); Statement query = connection.createStatement();
                ResultSet result = query.executeQuery(
                        "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")) {
            assertTrue(result.next());
            assertFalse(result.getBoolean(1));
            assertFalse(result.getBoolean(2));
        }
        signingKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new ProviderEvidenceVerifier(Map.of("local-test-receipt",
                new ProviderEvidenceVerifier.TrustKey(signingKey.getPublic(),
                        "local-signed-fixture-not-a-provider", "stripe", Set.of(RENEWAL, DUNNING),
                        START.minusSeconds(60), START.plus(Duration.ofDays(7)), false)),
                new JdbcProviderEvidenceReplayGuard(database), Duration.ofMinutes(5), Duration.ZERO);
        System.out.println("native_postgres_jvm_pid=" + ProcessHandle.current().pid()
                + " schema=" + SCHEMA + " provider_calls=0 channel_acceptance=NOT_RUN");
    }

    @Test
    void immediateCancellationIsDurableAndIdempotent() throws Exception {
        Fixture value = fixture();
        JdbcCommerceService service = service(START);
        service.scheduleCancellation(value.context(), value.id(), START, "customer_request",
                "immediate-cancel", "cancel-test");
        service.scheduleCancellation(value.context(), value.id(), START, "customer_request",
                "immediate-cancel", "cancel-test");
        assertEquals(CommerceService.SubscriptionState.CANCELED,
                service(START).getSubscription(value.context(), value.id()).state());
        assertEquals(1, count(value, "outbox_event", "aggregate_id", value.id(),
                " AND event_type='billing.subscription.canceled.v1'"));
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").isEmpty());
        assertThrows(CommerceRuntimeException.class, () -> service.recordUsage(value.context(),
                value.id(), 1, "usage-after-cancel", "cancel-test"));
        proof(value);
    }

    @Test
    void immediateRequestUsesServerTimeWithoutRetrospectiveCredit() throws Exception {
        Fixture value = fixture();
        var adjustment = service(START.plusSeconds(30)).scheduleCancellation(value.context(),
                value.id(), START.plusSeconds(5), "client-clock-lag", "clock-lag-cancel", "cancel-test");
        assertEquals(30, adjustment.remainingSeconds());
        assertEquals(50, adjustment.oldUnusedCreditMinor());
        assertEquals(START.plusSeconds(30), service(END).getSubscription(value.context(), value.id()).cancelAt());
        assertEquals(CommerceService.SubscriptionState.CANCELED,
                service(END).getSubscription(value.context(), value.id()).state());
        proof(value);
    }

    @Test
    void overdueImmediateCancellationDoesNotInventCreditOrNewPeriods() throws Exception {
        Fixture value = fixture();
        var adjustment = service(END.plusSeconds(10)).scheduleCancellation(value.context(),
                value.id(), END.plusSeconds(10), "overdue-cancel", "overdue-cancel", "cancel-test");
        assertEquals(0, adjustment.remainingSeconds());
        assertEquals(0, adjustment.oldUnusedCreditMinor());
        assertEquals(END, service(END).getSubscription(value.context(), value.id()).cancelAt());
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").isEmpty());
        proof(value);
    }

    @Test
    void periodEndCancellationWinsOverRenewalAfterRestart() throws Exception {
        Fixture value = fixture();
        service(START).scheduleCancellation(value.context(), value.id(), END, "period_end",
                "future-cancel", "cancel-test");
        assertEquals(CommerceService.SubscriptionState.ACTIVE,
                service(START).getSubscription(value.context(), value.id()).state());
        assertThrows(CommerceRuntimeException.class, () -> service(END).recordUsage(
                value.context(), value.id(), 1, "usage-at-cancel-deadline", "cancel-test"));
        assertThrows(CommerceRuntimeException.class, () -> service(END.plusSeconds(1)).recordUsage(
                value.context(), value.id(), 1, "usage-after-cancel-deadline", "cancel-test"));
        assertEquals(0, count(value, "subscription_usage_inbox", "subscription_id", value.id(), ""));
        assertEquals(0, service(END).getSubscription(value.context(), value.id()).usageQuantity());
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").isEmpty());
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").isEmpty());
        assertEquals(CommerceService.SubscriptionState.CANCELED,
                service(END).getSubscription(value.context(), value.id()).state());
        assertEquals(0, count(value, "subscription_billing_cycle", "subscription_id", value.id(), ""));
        assertEquals(1, count(value, "outbox_event", "aggregate_id", value.id(),
                " AND event_type='billing.subscription.canceled.v1'"));
        proof(value);
    }

    @Test
    void lateVerifiedSuccessIsRetainedWithoutReactivatingCancellation() throws Exception {
        Fixture value = fixture();
        service(START).recordUsage(value.context(), value.id(), 1, "positive-debit-usage", "cancel-test");
        CommerceService.BillingCycle cycle = service(END)
                .enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").orElseThrow();
        service(END).scheduleCancellation(value.context(), value.id(), END, "period_end",
                "inflight-cancel", "cancel-test");
        String resultDigest = "a".repeat(64);
        ProviderEvidenceReceipt receipt = receipt(value, cycle.id(), RENEWAL, "succeeded", resultDigest, null);
        service(END).recordRenewalOutcome(value.context(), cycle.id(),
                CommerceService.RenewalOutcome.SUCCEEDED, resultDigest, receipt, "late-success", "cancel-test");
        service(END).recordRenewalOutcome(value.context(), cycle.id(),
                CommerceService.RenewalOutcome.SUCCEEDED, resultDigest, receipt, "late-success", "cancel-test");
        CommerceService.Subscription stored = service(END).getSubscription(value.context(), value.id());
        assertEquals(CommerceService.SubscriptionState.CANCELED, stored.state());
        assertEquals(END, stored.periodEnd());
        assertEquals(END, stored.cancelAt());
        assertEquals(1, count(value, "subscription_billing_cycle", "id", cycle.id(), " AND state='succeeded'"));
        proof(value);
    }

    @Test
    void unknownOrFailedLateResultDoesNotOpenFreshDunning() throws Exception {
        for (CommerceService.RenewalOutcome outcome : new CommerceService.RenewalOutcome[] {
                CommerceService.RenewalOutcome.UNKNOWN, CommerceService.RenewalOutcome.FAILED}) {
            Fixture value = fixture();
            service(START).recordUsage(value.context(), value.id(), 1, "positive-debit-usage", "cancel-test");
            CommerceService.BillingCycle cycle = service(END)
                    .enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").orElseThrow();
            service(END).scheduleCancellation(value.context(), value.id(), END, "period_end",
                    "cancel-before-result", "cancel-test");
            String digest = "b".repeat(64);
            service(END).recordRenewalOutcome(value.context(), cycle.id(), outcome, digest,
                    receipt(value, cycle.id(), RENEWAL, outcome.name().toLowerCase(java.util.Locale.ROOT), digest, null),
                    "late-result", "cancel-test");
            assertEquals(CommerceService.SubscriptionState.CANCELED,
                    service(END).getSubscription(value.context(), value.id()).state());
            assertEquals(0, count(value, "dunning_case", "subscription_id", value.id(), ""));
            assertEquals(1, count(value, "subscription_billing_cycle", "id", cycle.id(),
                    " AND state='" + outcome.name().toLowerCase(java.util.Locale.ROOT) + "'"));
            proof(value);
        }
    }

    @Test
    void scheduledDunningIsNotDispatchedAfterCancellation() throws Exception {
        Fixture value = fixture();
        service(START).recordUsage(value.context(), value.id(), 1, "positive-debit-usage", "cancel-test");
        CommerceService.BillingCycle cycle = service(END)
                .enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").orElseThrow();
        String digest = "e".repeat(64);
        service(END).recordRenewalOutcome(value.context(), cycle.id(), CommerceService.RenewalOutcome.FAILED,
                digest, receipt(value, cycle.id(), RENEWAL, "failed", digest, null), "failed-renewal", "cancel-test");
        service(END).scheduleCancellation(value.context(), value.id(), END, "customer_request",
                "cancel-before-dunning", "cancel-test");
        assertTrue(service(END.plus(Duration.ofDays(2))).enqueueDueDunning(
                value.context().tenantId(), END.plus(Duration.ofDays(2)), "cancel-test").isEmpty());
        assertEquals(1, count(value, "dunning_case", "subscription_id", value.id(),
                " AND attempts=0 AND state='scheduled'"));
        proof(value);
    }

    @Test
    void canceledSubscriptionCannotBeReactivatedByDunning() throws Exception {
        Fixture value = fixture();
        service(START).recordUsage(value.context(), value.id(), 1, "positive-debit-usage", "cancel-test");
        CommerceService.BillingCycle cycle = service(END)
                .enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").orElseThrow();
        String digest = "c".repeat(64);
        service(END).recordRenewalOutcome(value.context(), cycle.id(), CommerceService.RenewalOutcome.FAILED,
                digest, receipt(value, cycle.id(), RENEWAL, "failed", digest, null), "failure", "cancel-test");
        UUID dunningId;
        try (Connection connection = tenantConnection(value.context().tenantId());
                PreparedStatement statement = connection.prepareStatement(
                        "UPDATE dunning_case SET state='waiting_provider_query',attempts=1 "
                                + "WHERE subscription_id=? RETURNING id")) {
            statement.setObject(1, value.id());
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                dunningId = result.getObject(1, UUID.class);
            }
            connection.commit();
        }
        service(END).scheduleCancellation(value.context(), value.id(), END, "customer_request",
                "cancel-dunning", "cancel-test");
        service(END).recordDunningOutcome(value.context(), dunningId,
                CommerceService.RenewalOutcome.SUCCEEDED, digest,
                receipt(value, dunningId, DUNNING, "succeeded", digest, "1"), "late-dunning", "cancel-test");
        assertEquals(CommerceService.SubscriptionState.CANCELED,
                service(END).getSubscription(value.context(), value.id()).state());
        assertTrue(service(END.plus(Duration.ofDays(2))).enqueueDueDunning(
                value.context().tenantId(), END.plus(Duration.ofDays(2)), "cancel-test").isEmpty());
        proof(value);
    }

    @Test
    void concurrentCancellationAndRenewalRemainSerializable() throws Exception {
        Fixture value = fixture();
        service(START).recordUsage(value.context(), value.id(), 1, "positive-debit-usage", "cancel-test");
        CountDownLatch start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var cancellation = workers.submit(() -> {
                await(start);
                retrySerialization(() -> service(END).scheduleCancellation(value.context(), value.id(),
                        END, "period_end", "race-cancel", "cancel-test"));
            });
            var renewal = workers.submit(() -> {
                await(start);
                retrySerialization(() -> service(END).enqueueDueRenewal(
                        value.context().tenantId(), END, "cancel-test"));
            });
            start.countDown();
            cancellation.get(30, TimeUnit.SECONDS);
            renewal.get(30, TimeUnit.SECONDS);
        }
        assertEquals(CommerceService.SubscriptionState.CANCELED,
                service(END).getSubscription(value.context(), value.id()).state());
        assertTrue(service(END).enqueueDueRenewal(value.context().tenantId(), END, "cancel-test").isEmpty());
        assertTrue(count(value, "subscription_billing_cycle", "subscription_id", value.id(), "") <= 1);
        assertEquals(1, count(value, "outbox_event", "aggregate_id", value.id(),
                " AND event_type='billing.subscription.canceled.v1'"));
        proof(value);
    }

    @Test
    void anotherTenantCannotCancelOrReadTheSubscription() throws Exception {
        Fixture value = fixture();
        CommerceService.Context other = new CommerceService.Context(UUID.randomUUID(), UUID.randomUUID(), "test-other");
        assertThrows(CommerceRuntimeException.class, () -> service(START).scheduleCancellation(
                other, value.id(), START, "wrong-tenant", "wrong-cancel", "cancel-test"));
        assertThrows(CommerceRuntimeException.class, () -> service(START).getSubscription(other, value.id()));
        CommerceService.Context otherProject = new CommerceService.Context(
                value.context().tenantId(), UUID.randomUUID(), "test-other-project");
        assertThrows(CommerceRuntimeException.class, () -> service(START).scheduleCancellation(
                otherProject, value.id(), START, "wrong-project", "wrong-project-cancel", "cancel-test"));
        assertThrows(CommerceRuntimeException.class, () -> service(START).scheduleCancellation(
                value.context(), value.id(), START.minusSeconds(1), "invalid-past", "invalid-past", "cancel-test"));
        assertEquals(CommerceService.SubscriptionState.ACTIVE,
                service(START).getSubscription(value.context(), value.id()).state());
        proof(value);
    }

    @Test
    void productionBillingJobAppliesDueCancellationWithoutRenewing() throws Exception {
        Fixture value = fixture();
        service(START).scheduleCancellation(value.context(), value.id(), END,
                "period_end", "job-cancel", "cancel-test");
        Class<?> jobType = Class.forName("com.elmpay.scheduler.BillingLifecycleJob");
        Object job = jobType.getConstructor(CommerceService.class, int.class).newInstance(service(END), 1);
        Object result = jobType.getMethod("run", UUID.class, String.class, Instant.class)
                .invoke(job, value.context().tenantId(), "cancel-job", END);
        assertEquals(0, result.getClass().getMethod("renewalEvents").invoke(result));
        assertEquals(0, result.getClass().getMethod("dunningEvents").invoke(result));
        assertEquals(CommerceService.SubscriptionState.CANCELED,
                service(END).getSubscription(value.context(), value.id()).state());
        assertEquals(0, count(value, "subscription_billing_cycle", "subscription_id", value.id(), ""));
        proof(value);
    }

    @Test
    void cancellationEventAdvancesRealLedgerConsumerWithoutPostingMoney() throws Exception {
        Fixture value = fixture();
        service(START).scheduleCancellation(value.context(), value.id(), START,
                "customer_request", "cancel-ledger", "cancel-test");
        // worker-scheduler is a runtimeOnly Gradle dependency of the gateway. Reflection
        // loads its real classes; no proxy, replacement consumer, or fake ledger is used.
        Class<?> deliveryType = Class.forName("com.elmpay.scheduler.events.JdbcEventDeliveryStore");
        Class<?> ledgerType = Class.forName("com.elmpay.ledger.LedgerService");
        Class<?> resolverType = Class.forName("com.elmpay.scheduler.LedgerPostingConsumer$PostingPolicyResolver");
        Class<?> messageType = Class.forName("com.elmpay.scheduler.events.JdbcEventDeliveryStore$InboxMessage");
        Class<?> consumerType = Class.forName("com.elmpay.scheduler.LedgerPostingConsumer");
        Object consumer = consumerType.getConstructor(deliveryType, ledgerType, resolverType,
                Duration.class, Duration.class).newInstance(
                        deliveryType.getConstructor(DataSource.class).newInstance(database),
                        ledgerType.getConstructor(DataSource.class, Clock.class).newInstance(
                                database, Clock.fixed(START, ZoneOffset.UTC)),
                        Class.forName("com.elmpay.scheduler.JdbcPostingPolicyResolver").getConstructor().newInstance(),
                        Duration.ofSeconds(30), Duration.ofSeconds(1));
        var constructor = messageType.getConstructor(UUID.class, UUID.class, UUID.class, String.class,
                UUID.class, long.class, String.class, int.class, String.class,
                Instant.class, Instant.class, String.class);
        var consume = consumerType.getMethod("consume", messageType, String.class, Instant.class);
        int consumed = 0;
        try (Connection connection = tenantConnection(value.context().tenantId());
                PreparedStatement query = connection.prepareStatement(
                        "SELECT * FROM outbox_event WHERE aggregate_id=? ORDER BY aggregate_revision")) {
            query.setObject(1, value.id());
            try (ResultSet rows = query.executeQuery()) {
                while (rows.next()) {
                    Object message = constructor.newInstance(rows.getObject("id", UUID.class),
                            value.context().tenantId(), value.context().projectId(), rows.getString("aggregate_type"),
                            value.id(), rows.getLong("aggregate_revision"), rows.getString("event_type"),
                            rows.getInt("event_version"), rows.getString("payload"), rows.getTimestamp("occurred_at").toInstant(),
                            rows.getTimestamp("recorded_at").toInstant(), rows.getString("trace_id"));
                    assertEquals("APPLIED", consume.invoke(consumer, message, "cancel-ledger", START).toString());
                    assertEquals("DUPLICATE", consume.invoke(consumer, message, "cancel-ledger", START).toString());
                    consumed++;
                }
            }
        }
        assertEquals(2, consumed, "created and canceled subscription events must both be consumed");
        assertEquals(0, count(value, "ledger_transaction", "tenant_id", value.context().tenantId(), ""));
        assertEquals(1, count(value, "ledger_event_revision_guard", "aggregate_id", value.id(),
                " AND last_revision=2"));
        proof(value);
    }

    private static Fixture fixture() {
        CommerceService.Context context = new CommerceService.Context(UUID.randomUUID(), UUID.randomUUID(), "test-operator");
        JdbcCommerceService service = service(START);
        var plan = service.createPlan(context, new CommerceService.PlanCommand(
                "synthetic", 100, "USD", 60, 0, true, 1), "plan", "cancel-test");
        var mandate = service.createMandate(context, new CommerceService.MandateCommand(
                "synthetic-customer", "stripe", "synthetic-mandate", "psp://stripe/synthetic",
                "renewal", 1000, "USD", "d".repeat(64)), "mandate", "cancel-test");
        return new Fixture(context, service.createSubscription(context,
                new CommerceService.SubscriptionCommand("synthetic-customer", plan.id(), mandate.id()),
                "subscribe", "cancel-test").id());
    }

    private static JdbcCommerceService service(Instant now) {
        return new JdbcCommerceService(database, Clock.fixed(now, ZoneOffset.UTC), verifier);
    }

    private static ProviderEvidenceReceipt receipt(Fixture value, UUID entity, String type,
            String outcome, String digest, String attempt) throws Exception {
        Map<String, String> fields = new LinkedHashMap<>(Map.of("tenantId", value.context().tenantId().toString(),
                "projectId", value.context().projectId().toString(), "provider", "stripe", "entityId", entity.toString(),
                "subscriptionId", value.id().toString(), "result", outcome, "providerResultDigest", digest));
        fields.put(type.equals(RENEWAL) ? "billingCycleId" : "dunningCaseId", entity.toString());
        if (attempt != null) fields.put("attempt", attempt);
        ProviderEvidenceReceipt unsigned = new ProviderEvidenceReceipt(type, fields,
                "local-test-receipt", END.minusSeconds(1), END.plusSeconds(120), UUID.randomUUID().toString(), new byte[64]);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(signingKey.getPrivate());
        signer.update(ProviderEvidenceVerifier.signaturePayload(unsigned));
        return new ProviderEvidenceReceipt(type, fields, unsigned.keyId(), unsigned.issuedAt(), unsigned.expiresAt(),
                unsigned.nonce(), signer.sign());
    }

    private static Connection tenantConnection(UUID tenant) throws SQLException {
        Connection connection = database.getConnection();
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement("SELECT set_config('app.tenant_id',?,true)")) {
            statement.setString(1, tenant.toString());
            statement.execute();
        }
        return connection;
    }

    private static long count(Fixture value, String table, String column, UUID id, String predicate) throws SQLException {
        try (Connection connection = tenantConnection(value.context().tenantId());
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT count(*) FROM " + table + " WHERE " + column + "=?" + predicate)) {
            statement.setObject(1, id);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getLong(1);
            }
        }
    }

    private static void proof(Fixture value) throws Exception {
        try (Connection connection = tenantConnection(value.context().tenantId());
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT row_to_json(s)::text FROM billing_subscription s WHERE id=?")) {
            statement.setObject(1, value.id());
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(result.getString(1).getBytes(StandardCharsets.UTF_8)));
                System.out.println("subscription=" + value.id() + " db_post_image_sha256=" + sha);
            }
        }
    }

    private static void await(CountDownLatch start) {
        try { start.await(); }
        catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    private static void retrySerialization(Runnable action) {
        for (int attempt = 0; attempt < 4; attempt++) {
            try { action.run(); return; }
            catch (CommerceRuntimeException failure) {
                if (attempt == 3 || !(failure.getCause() instanceof SQLException sql)
                        || !("40001".equals(sql.getSQLState()) || "40P01".equals(sql.getSQLState()))) throw failure;
            }
        }
        throw new AssertionError("bounded transaction retry exhausted");
    }

    private record Fixture(CommerceService.Context context, UUID id) {}

    private record RealPostgresDataSource(String url, String user) implements DataSource {
        @Override public Connection getConnection() throws SQLException { return getConnection(user, ""); }
        @Override public Connection getConnection(String username, String password) throws SQLException {
            Connection connection = DriverManager.getConnection(url, username, password);
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET ROLE " + ROLE);
                statement.execute("SET search_path TO " + SCHEMA + ",public");
                return connection;
            } catch (SQLException failure) { connection.close(); throw failure; }
        }
        @Override public PrintWriter getLogWriter() { return DriverManager.getLogWriter(); }
        @Override public void setLogWriter(PrintWriter writer) { DriverManager.setLogWriter(writer); }
        @Override public void setLoginTimeout(int seconds) { DriverManager.setLoginTimeout(seconds); }
        @Override public int getLoginTimeout() { return DriverManager.getLoginTimeout(); }
        @Override public Logger getParentLogger() { return Logger.getLogger("java.sql"); }
        @Override public boolean isWrapperFor(Class<?> type) { return type.isInstance(this); }
        @Override public <T> T unwrap(Class<T> type) throws SQLException {
            if (type.isInstance(this)) return type.cast(this);
            throw new SQLException("not a wrapper for requested type");
        }
    }
}
