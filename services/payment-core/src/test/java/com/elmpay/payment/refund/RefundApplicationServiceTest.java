package com.elmpay.payment.refund;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.merchant.AccountStatus;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.merchant.ProviderRoute;
import com.elmpay.merchant.RoutingRequest;
import com.elmpay.money.Money;
import com.elmpay.payment.AttemptDraft;
import com.elmpay.payment.AttemptOperation;
import com.elmpay.payment.AttemptResolution;
import com.elmpay.payment.AttemptState;
import com.elmpay.payment.ConfirmationMode;
import com.elmpay.payment.InMemoryPaymentRepository;
import com.elmpay.payment.IntentState;
import com.elmpay.payment.OutcomeClass;
import com.elmpay.payment.PaymentAttempt;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.PaymentIntent;
import com.elmpay.payment.ProviderAdapterRegistry;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import com.elmpay.security.SecretReference;
import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class RefundApplicationServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static final String DEVICE_DIGEST = "a".repeat(64);

    @Test
    void exactProviderSuccessIsDurableAndCreateReplayDoesNotDoubleRefund() {
        Fixture fixture = new Fixture((context) -> RefundRiskDecision.AUTO_APPROVE);
        fixture.adapter.refundResult = new ProviderRefund("provider-refund-1",
                ProviderOutcome.SUCCEEDED, Money.of(600, "USD"), true);
        RefundRequestCommand command = fixture.request("refund-create-0001", 600,
                RefundReason.CUSTOMER_REQUEST, "alice");

        RefundRecord created = fixture.service.request(command);
        RefundRecord replay = fixture.service.request(command);

        assertEquals(RefundStatus.SUCCEEDED, created.status());
        assertEquals(created, replay);
        assertEquals(1, fixture.adapter.refundCalls.get());
        assertEquals(400, fixture.service.remainingRefundable(fixture.tenantId,
                fixture.intent.id()));
        assertEquals(List.of("refund.requested.v1", "refund.succeeded.v1"),
                fixture.refunds.outboxEvents().stream().map(RefundOutboxEvent::eventType).toList());

        PaymentCoreException conflict = assertThrows(PaymentCoreException.class,
                () -> fixture.service.request(fixture.request("refund-create-0001", 500,
                        RefundReason.CUSTOMER_REQUEST, "alice")));
        assertEquals("IDEMPOTENCY_KEY_REUSE", conflict.code());
    }

    @Test
    void manualPolicyRequiresIndependentApproverAndApprovalReplayIsSideEffectFree() {
        Fixture fixture = new Fixture((context) -> RefundRiskDecision.REQUIRE_APPROVAL);
        fixture.adapter.refundResult = new ProviderRefund("provider-refund-2",
                ProviderOutcome.SUCCEEDED, Money.of(700, "USD"), true);
        RefundRecord requested = fixture.service.request(fixture.request(
                "refund-create-0002", 700, RefundReason.DUPLICATE, "alice"));
        assertEquals(RefundStatus.APPROVAL_PENDING, requested.status());
        assertEquals(300, fixture.service.remainingRefundable(fixture.tenantId,
                fixture.intent.id()));

        RefundApprovalCommand selfApproval = new RefundApprovalCommand(fixture.tenantId,
                requested.id(), "alice", "confirmed duplicate", "ticket-10",
                "refund-approve-001", "corr-approve-1");
        PaymentCoreException fourEyes = assertThrows(PaymentCoreException.class,
                () -> fixture.service.approve(selfApproval));
        assertEquals("REFUND_FOUR_EYES_REQUIRED", fourEyes.code());

        RefundApprovalCommand approval = new RefundApprovalCommand(fixture.tenantId,
                requested.id(), "bob", "confirmed duplicate", "ticket-10",
                "refund-approve-002", "corr-approve-2");
        RefundRecord approved = fixture.service.approve(approval);
        RefundRecord replay = fixture.service.approve(approval);
        assertEquals(RefundStatus.SUCCEEDED, approved.status());
        assertEquals(approved, replay);
        assertEquals("bob", approved.approverId());
        assertEquals(1, fixture.adapter.refundCalls.get());
        RefundOutboxEvent approvalEvent = fixture.refunds.outboxEvents().stream()
                .filter(event -> event.eventType().equals("refund.approved.v1"))
                .findFirst().orElseThrow();
        assertEquals("bob", approvalEvent.payload().get("actor_id"));
        assertEquals("ticket-10", approvalEvent.payload().get("ticket_id"));

        RefundApprovalCommand conflict = new RefundApprovalCommand(fixture.tenantId,
                requested.id(), "bob", "different reason", "ticket-10",
                "refund-approve-002", "corr-approve-2");
        assertEquals("IDEMPOTENCY_KEY_REUSE", assertThrows(PaymentCoreException.class,
                () -> fixture.service.approve(conflict)).code());
    }

    @Test
    void concurrentReservationsCannotExceedCapturedAmount() throws Exception {
        CountDownLatch evaluated = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        Fixture fixture = new Fixture((context) -> {
            evaluated.countDown();
            try {
                if (!release.await(5, TimeUnit.SECONDS)) {
                    throw new AssertionError("concurrent risk evaluation timed out");
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new AssertionError(exception);
            }
            return RefundRiskDecision.AUTO_APPROVE;
        });
        fixture.adapter.refundResult = new ProviderRefund("provider-refund-unknown",
                ProviderOutcome.UNKNOWN, null, false);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> outcome(() -> fixture.service.request(
                    fixture.request("refund-concurrent-01", 600, RefundReason.OTHER, "alice"))));
            var second = executor.submit(() -> outcome(() -> fixture.service.request(
                    fixture.request("refund-concurrent-02", 600, RefundReason.OTHER, "bob"))));
            assertTrue(evaluated.await(5, TimeUnit.SECONDS));
            release.countDown();
            List<Object> outcomes = List.of(first.get(10, TimeUnit.SECONDS),
                    second.get(10, TimeUnit.SECONDS));
            assertEquals(1, outcomes.stream().filter(RefundRecord.class::isInstance).count());
            PaymentCoreException rejected = outcomes.stream()
                    .filter(PaymentCoreException.class::isInstance)
                    .map(PaymentCoreException.class::cast).findFirst().orElseThrow();
            assertEquals("REFUND_AMOUNT_EXCEEDS_REFUNDABLE", rejected.code());
        }
        assertEquals(1, fixture.adapter.refundCalls.get());
        assertEquals(400, fixture.service.remainingRefundable(fixture.tenantId,
                fixture.intent.id()));
    }

    @Test
    void unknownTransportOutcomeConvergesOnlyThroughExactProviderQuery() {
        Fixture fixture = new Fixture((context) -> RefundRiskDecision.AUTO_APPROVE);
        fixture.adapter.refundFailure = new ProviderException("PROVIDER_TIMEOUT",
                "timeout", true, true);
        RefundRecord unknown = fixture.service.request(fixture.request(
                "refund-create-0003", 1000, RefundReason.SERVICE_FAILURE, "alice"));
        assertEquals(RefundStatus.UNKNOWN, unknown.status());
        assertEquals(0, fixture.service.remainingRefundable(fixture.tenantId,
                fixture.intent.id()));

        fixture.adapter.refundFailure = null;
        fixture.adapter.queryResult = new ProviderRefund("provider-refund-3",
                ProviderOutcome.SUCCEEDED, Money.of(1000, "USD"), true);
        RefundRecoveryCommand recovery = new RefundRecoveryCommand(fixture.tenantId,
                unknown.id(), "worker", "incident-44", "refund-recover-001",
                "corr-recover-1");
        RefundRecord succeeded = fixture.service.recover(recovery);
        RefundRecord replay = fixture.service.recover(recovery);
        assertEquals(RefundStatus.SUCCEEDED, succeeded.status());
        assertEquals(succeeded, replay);
        assertEquals(1, fixture.adapter.queryCalls.get());
    }

    @Test
    void mismatchedProviderMoneyNeverBecomesSuccessful() {
        Fixture fixture = new Fixture((context) -> RefundRiskDecision.AUTO_APPROVE);
        fixture.adapter.refundResult = new ProviderRefund("provider-refund-4",
                ProviderOutcome.SUCCEEDED, Money.of(999, "USD"), true);
        RefundRecord refund = fixture.service.request(fixture.request(
                "refund-create-0004", 1000, RefundReason.OTHER, "alice"));
        assertEquals(RefundStatus.UNKNOWN, refund.status());
        assertEquals("PROVIDER_REFUND_AMOUNT_MISMATCH", refund.failureCode());
        assertEquals(0, fixture.service.remainingRefundable(fixture.tenantId,
                fixture.intent.id()));
    }

    @Test
    void riskDenialIsPersistedIdempotentlyAndNeverCallsProvider() {
        Fixture fixture = new Fixture((context) -> RefundRiskDecision.DENY);
        RefundRequestCommand command = fixture.request("refund-create-deny", 100,
                RefundReason.FRAUDULENT, "alice");
        assertEquals("REFUND_RISK_DENIED", assertThrows(PaymentCoreException.class,
                () -> fixture.service.request(command)).code());
        assertEquals("REFUND_RISK_DENIED", assertThrows(PaymentCoreException.class,
                () -> fixture.service.request(command)).code());
        assertEquals(0, fixture.adapter.refundCalls.get());
        assertEquals(1, fixture.refunds.outboxEvents().size());
        assertEquals("refund.request.denied.v1",
                fixture.refunds.outboxEvents().getFirst().eventType());
    }

    @Test
    void tenantBoundaryHidesRefundAndMigrationForcesRls() throws IOException {
        Fixture fixture = new Fixture((context) -> RefundRiskDecision.REQUIRE_APPROVAL);
        RefundRecord refund = fixture.service.request(fixture.request(
                "refund-create-0005", 100, RefundReason.OTHER, "alice"));
        UUID otherTenant = UUID.randomUUID();
        assertEquals("RESOURCE_NOT_FOUND", assertThrows(PaymentCoreException.class,
                () -> fixture.service.get(otherTenant, refund.id())).code());

        try (InputStream stream = getClass().getResourceAsStream(
                "/db/migration/V034__durable_refund_runtime.sql")) {
            assertFalse(stream == null);
            String sql = new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(sql.contains("ALTER TABLE refund FORCE ROW LEVEL SECURITY"));
            assertTrue(sql.contains("PRIMARY KEY (tenant_id, idempotency_key)"));
            assertTrue(sql.contains("refund_four_eyes_check"));
            assertTrue(sql.contains("refund_payment_reservation_lookup"));
        }
    }

    @Test
    void rulesPolicyUsesRoleDeviceAnomalyAmountAgeAndMerchantRule() {
        RefundRequestCommand command = new RefundRequestCommand(UUID.randomUUID(),
                UUID.randomUUID(), 100, RefundReason.OTHER, "actor", DEVICE_DIGEST,
                "refund-risk-key-01", "corr-risk");
        PaymentIntent intent = Fixture.intent(command.tenantId(), command.paymentIntentId(), 1000);
        RefundRiskPolicy.Context context = new RefundRiskPolicy.Context(intent, command, NOW);

        RulesRefundRiskPolicy auto = new RulesRefundRiskPolicy(ignored ->
                new RulesRefundRiskPolicy.Signals("support", true, 1, 500,
                        Duration.ofDays(90), false), 50, 90);
        assertEquals(RefundRiskDecision.AUTO_APPROVE, auto.decide(context));
        RulesRefundRiskPolicy review = new RulesRefundRiskPolicy(ignored ->
                new RulesRefundRiskPolicy.Signals("support", false, 1, 500,
                        Duration.ofDays(90), false), 50, 90);
        assertEquals(RefundRiskDecision.REQUIRE_APPROVAL, review.decide(context));
        RulesRefundRiskPolicy deny = new RulesRefundRiskPolicy(ignored ->
                new RulesRefundRiskPolicy.Signals("viewer", true, 1, 500,
                        Duration.ofDays(90), false), 50, 90);
        assertEquals(RefundRiskDecision.DENY, deny.decide(context));
    }

    private static Object outcome(ThrowingSupplier supplier) {
        try {
            return supplier.get();
        } catch (PaymentCoreException exception) {
            return exception;
        }
    }

    @FunctionalInterface
    private interface ThrowingSupplier {
        RefundRecord get();
    }

    private static final class Fixture {
        private final UUID tenantId = UUID.randomUUID();
        private final UUID projectId = UUID.randomUUID();
        private final UUID merchantId = UUID.randomUUID();
        private final UUID accountId = UUID.randomUUID();
        private final InMemoryPaymentRepository payments = new InMemoryPaymentRepository();
        private final InMemoryRefundRepository refunds = new InMemoryRefundRepository();
        private final FakeAdapter adapter = new FakeAdapter();
        private final PaymentIntent intent;
        private final RefundApplicationService service;

        private Fixture(RefundRiskPolicy riskPolicy) {
            intent = intent(tenantId, UUID.randomUUID(), 1000, projectId, merchantId);
            payments.create(intent);
            PaymentAttempt initiated = payments.beginAttempt(new AttemptDraft(tenantId,
                    intent.id(), accountId, "stripe", AttemptOperation.PAYMENT, 0,
                    "b".repeat(64), "payment-attempt-001", NOW.minusSeconds(60)));
            PaymentAttempt succeeded = initiated.resolve(new AttemptResolution(
                    AttemptState.SUCCEEDED, OutcomeClass.SUCCEEDED, "c".repeat(64),
                    "provider-request-1", "provider-payment-1", "stripe.normalized",
                    "SUCCEEDED", NOW.minusSeconds(59)));
            payments.resolveAttempt(succeeded, intent, 0, "payment.succeeded.v1", "corr-pay");
            ProviderAccount account = new ProviderAccount(accountId, tenantId, projectId,
                    merchantId, "stripe", "sandbox", "merchant-provider-1",
                    SecretReference.parse("vault://payments/stripe"), "v1",
                    AccountStatus.ACTIVE);
            MerchantConfigurationRepository merchantRepository =
                    new MerchantConfigurationRepository() {
                        @Override
                        public Optional<ProviderAccount> findAccount(UUID tenant, UUID project,
                                UUID id) {
                            return account.tenantId().equals(tenant)
                                    && account.projectId().equals(project) && account.id().equals(id)
                                    ? Optional.of(account) : Optional.empty();
                        }

                        @Override
                        public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
                            return List.of();
                        }
                    };
            service = new RefundApplicationService(refunds, payments, merchantRepository,
                    new ProviderAdapterRegistry(List.of(adapter)), riskPolicy,
                    (providerAccount, paymentIntent, amount, reason) -> {
                        if (!providerAccount.id().equals(accountId)) {
                            throw new PaymentCoreException("REFUND_CAPABILITY_MISSING",
                                    "refund account capability is missing");
                        }
                    }, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO);
        }

        private RefundRequestCommand request(String key, long amount, RefundReason reason,
                String requester) {
            return new RefundRequestCommand(tenantId, intent.id(), amount, reason, requester,
                    DEVICE_DIGEST, key, "corr-" + key);
        }

        private static PaymentIntent intent(UUID tenantId, UUID intentId, long captured) {
            return intent(tenantId, intentId, captured, UUID.randomUUID(), UUID.randomUUID());
        }

        private static PaymentIntent intent(UUID tenantId, UUID intentId, long captured,
                UUID projectId, UUID merchantId) {
            return new PaymentIntent(intentId, tenantId, projectId, merchantId,
                    "business-order-1", Money.of(captured, "USD"), captured, 0,
                    IntentState.CAPTURED, Set.of("stripe_card"), ConfirmationMode.AUTOMATIC,
                    "US", "payment-create-001", NOW.plus(Duration.ofDays(1)),
                    NOW.minus(Duration.ofDays(1)), NOW.minusSeconds(60), 0);
        }
    }

    private static final class FakeAdapter implements ProviderAdapter {
        private final AtomicInteger refundCalls = new AtomicInteger();
        private final AtomicInteger queryCalls = new AtomicInteger();
        private ProviderRefund refundResult;
        private ProviderRefund queryResult;
        private ProviderException refundFailure;

        @Override
        public String provider() {
            return "stripe";
        }

        @Override
        public ProviderRefund refund(RefundCommand command) {
            refundCalls.incrementAndGet();
            if (refundFailure != null) {
                throw refundFailure;
            }
            return refundResult;
        }

        @Override
        public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
                String refundReference) {
            queryCalls.incrementAndGet();
            return queryResult;
        }

        @Override
        public ProviderPayment createPayment(CreatePaymentCommand command) {
            throw new UnsupportedOperationException();
        }

        @Override
        public ProviderPayment queryPayment(ProviderRequestContext context,
                String providerPaymentId, String businessOrderNo) {
            throw new UnsupportedOperationException();
        }

        @Override
        public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId,
                Money amount) {
            throw new UnsupportedOperationException();
        }

        @Override
        public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId,
                String reason) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            throw new UnsupportedOperationException();
        }
    }
}
