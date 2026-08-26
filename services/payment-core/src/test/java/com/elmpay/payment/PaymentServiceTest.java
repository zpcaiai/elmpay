package com.elmpay.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.merchant.AccountStatus;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.merchant.ProviderCapability;
import com.elmpay.merchant.ProviderRoute;
import com.elmpay.merchant.RoutingRequest;
import com.elmpay.merchant.RoutingService;
import com.elmpay.money.Money;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class PaymentServiceTest {
    private static final UUID TENANT = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("10000000-0000-0000-0000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("10000000-0000-0000-0000-000000000003");
    private static final UUID ACCOUNT_ID = UUID.fromString("10000000-0000-0000-0000-000000000004");
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-26T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void createReplaysOnlyAnIdenticalSnapshot() {
        FakeAdapter adapter = new FakeAdapter();
        PaymentService service = service(adapter);
        CreateIntentCommand command = createCommand("safe-create-key-0001", "order-1");
        PaymentIntent first = service.create(command);
        assertSame(first, service.create(command));
        assertThrows(PaymentCoreException.class,
                () -> service.create(createCommand("safe-create-key-0001", "order-2")));
    }

    @Test
    void createReplayBindsTheOriginalTimeToLive() {
        PaymentService service = service(new FakeAdapter());
        CreateIntentCommand original = createCommand(
                "safe-create-ttl-key-0001", "order-ttl", Duration.ofHours(1));
        service.create(original);
        PaymentCoreException exception = assertThrows(PaymentCoreException.class,
                () -> service.create(createCommand("safe-create-ttl-key-0001", "order-ttl",
                        Duration.ofHours(2))));

        assertEquals("IDEMPOTENCY_KEY_REUSE", exception.code());
    }

    @Test
    void confirmedProviderResultCapturesExactlyOnce() {
        FakeAdapter adapter = new FakeAdapter();
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(createCommand("safe-create-key-0002", "order-2"));
        ConfirmationCommand command = confirmation(intent, "safe-confirm-key-0001");
        ConfirmationResult first = service.confirm(command);
        ConfirmationResult replay = service.confirm(command);
        assertEquals(IntentState.CAPTURED, first.intent().state());
        assertEquals(1_000, first.intent().capturedAmountMinor());
        assertEquals(1, adapter.calls.get());
        assertEquals(true, replay.replayed());
    }

    @Test
    void concurrentConfirmationsDispatchOnlyOneProviderCall() throws Exception {
        FakeAdapter adapter = new FakeAdapter();
        adapter.block = true;
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(createCommand("safe-create-key-0003", "order-3"));
        int contenders = 12;
        try (var executor = Executors.newFixedThreadPool(contenders)) {
            CountDownLatch started = new CountDownLatch(contenders);
            CountDownLatch done = new CountDownLatch(contenders);
            for (int index = 0; index < contenders; index++) {
                String key = "safe-concurrent-key-" + String.format("%04d", index);
                executor.submit(() -> {
                    started.countDown();
                    try {
                        service.confirm(confirmation(intent, key));
                    } catch (PaymentCoreException expected) {
                        // Losing reservations fail before provider dispatch.
                    } finally {
                        done.countDown();
                    }
                });
            }
            started.await(2, TimeUnit.SECONDS);
            adapter.release.countDown();
            done.await(5, TimeUnit.SECONDS);
        }
        assertEquals(1, adapter.calls.get());
        assertEquals(IntentState.CAPTURED, service.get(TENANT, intent.id()).state());
    }

    @Test
    void untrustedSuccessAndCardLikeReferencesAreRejected() {
        PaymentIntent intent = PaymentIntent.create(
                createCommand("safe-create-key-0004", "order-4"), CLOCK);
        assertThrows(PaymentCoreException.class, () -> new PaymentStateMachine().transition(intent,
                IntentState.AUTHORIZED, AuthoritySource.MERCHANT_REQUEST, CLOCK.instant()));
        assertThrows(IllegalArgumentException.class, () -> PaymentMethodReference.parse(
                "card", "psp://4242424242424242", "fingerprint"));
    }

    @Test
    void idempotencyKeyIsBoundToOperationAndCanonicalPayload() {
        FakeAdapter adapter = new FakeAdapter();
        adapter.createResponse = authorized("provider-payment-idempotency");
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(
                createCommand("safe-create-key-idem-0001", "order-idem"));
        String confirmKey = "safe-shared-action-key-0001";
        service.confirm(confirmation(intent, confirmKey));

        PaymentCoreException crossOperation = assertThrows(PaymentCoreException.class,
                () -> service.capture(new CaptureCommand(TENANT, intent.id(), 400,
                        confirmKey, "correlation-capture-cross-operation")));
        assertEquals("IDEMPOTENCY_KEY_REUSE", crossOperation.code());
        assertEquals(0, adapter.captureCalls.get());

        String captureKey = "safe-capture-payload-key-0001";
        service.capture(new CaptureCommand(TENANT, intent.id(), 400, captureKey,
                "correlation-capture-first"));
        PaymentCoreException changedPayload = assertThrows(PaymentCoreException.class,
                () -> service.capture(new CaptureCommand(TENANT, intent.id(), 500,
                        captureKey, "correlation-capture-retry")));
        assertEquals("IDEMPOTENCY_KEY_REUSE", changedPayload.code());
        assertEquals(1, adapter.captureCalls.get());
    }

    @Test
    void confirmationReplayRejectsChangedPaymentPayload() {
        FakeAdapter adapter = new FakeAdapter();
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(
                createCommand("safe-create-key-idem-0002", "order-idem-confirm"));
        String key = "safe-confirm-payload-key-0001";
        service.confirm(confirmation(intent, key));

        ConfirmationCommand changed = new ConfirmationCommand(TENANT, intent.id(),
                PaymentMethodReference.parse("card", "psp://payment-method/different-reference",
                        "fp-different"), key, "correlation-confirm-retry", "checkout-complete",
                Map.of("merchant_option", "changed"));
        PaymentCoreException exception = assertThrows(PaymentCoreException.class,
                () -> service.confirm(changed));

        assertEquals("IDEMPOTENCY_KEY_REUSE", exception.code());
        assertEquals(1, adapter.calls.get());
    }

    @Test
    void successfulPaymentRequiresTrustedMatchingCapturedAmountAndCurrency() {
        assertConfirmationRejected(new ProviderPayment("request-missing", "payment-missing",
                ProviderOutcome.SUCCEEDED, Money.of(1_000, "USD"), null, true, Map.of()),
                "PROVIDER_AMOUNT_MISSING", "missing");
        assertConfirmationRejected(new ProviderPayment("request-currency", "payment-currency",
                ProviderOutcome.SUCCEEDED, Money.of(1_000, "EUR"), Money.of(1_000, "EUR"),
                true, Map.of()), "PROVIDER_CURRENCY_MISMATCH", "currency");
        assertConfirmationRejected(new ProviderPayment("request-amount", "payment-amount",
                ProviderOutcome.SUCCEEDED, Money.of(999, "USD"), Money.of(999, "USD"),
                true, Map.of()), "PROVIDER_AMOUNT_MISMATCH", "amount");
    }

    @Test
    void authorizationAndCaptureRequireTrustedMatchingAmounts() {
        assertConfirmationRejected(new ProviderPayment("request-auth", "payment-auth",
                ProviderOutcome.AUTHORIZED, null, null, true, Map.of()),
                "PROVIDER_AMOUNT_MISSING", "authorization");

        assertCaptureRejected(new ProviderPayment("request-capture-missing", "payment-capture",
                ProviderOutcome.SUCCEEDED, Money.of(400, "USD"), null, true, Map.of()),
                "PROVIDER_AMOUNT_MISSING", "capture-missing");
        assertCaptureRejected(new ProviderPayment("request-capture-currency", "payment-capture",
                ProviderOutcome.SUCCEEDED, Money.of(400, "EUR"), Money.of(400, "EUR"),
                true, Map.of()), "PROVIDER_CURRENCY_MISMATCH", "capture-currency");
        assertCaptureRejected(new ProviderPayment("request-capture-amount", "payment-capture",
                ProviderOutcome.SUCCEEDED, Money.of(401, "USD"), Money.of(401, "USD"),
                true, Map.of()), "PROVIDER_AMOUNT_MISMATCH", "capture-amount");
    }

    @Test
    void requiresActionAttemptDoesNotBlockFollowUpConfirmation() {
        FakeAdapter adapter = new FakeAdapter();
        adapter.createResponse = new ProviderPayment("request-action", "payment-action",
                ProviderOutcome.REQUIRES_ACTION, null, null, false,
                Map.of("redirect_url", "https://checkout.example/continue"));
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(
                createCommand("safe-create-action-key-0001", "order-action"));

        ConfirmationResult action = service.confirm(
                confirmation(intent, "safe-confirm-action-key-0001"));
        adapter.createResponse = null;
        ConfirmationResult completed = service.confirm(
                confirmation(intent, "safe-confirm-action-key-0002"));

        assertEquals(IntentState.REQUIRES_ACTION, action.intent().state());
        assertEquals(AttemptState.SUCCEEDED, action.attempt().state());
        assertEquals(IntentState.CAPTURED, completed.intent().state());
        assertEquals(2, adapter.calls.get());
    }

    @Test
    void definitiveQueryAtomicallyClosesOriginalUnknownAndQueryAttempts() {
        FakeAdapter adapter = new FakeAdapter();
        adapter.createResponse = unknown("payment-unknown-recovered");
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(
                createCommand("safe-create-recover-key-0001", "order-recover"));
        service.confirm(confirmation(intent, "safe-confirm-recover-key-0001"));
        adapter.queryResponse = success("payment-unknown-recovered");

        ConfirmationResult recovered = service.resolveUnknown(TENANT, intent.id(),
                "correlation-recovery");
        List<PaymentAttempt> attempts = service.attempts(TENANT, intent.id());

        assertEquals(IntentState.CAPTURED, recovered.intent().state());
        assertEquals(2, attempts.size());
        assertEquals(AttemptState.SUCCEEDED, attempts.get(0).state());
        assertEquals(AttemptState.SUCCEEDED, attempts.get(1).state());
    }

    @Test
    void invalidOrFailedUnknownQueryNeverLeavesAnInitiatedAttempt() {
        FakeAdapter invalidAdapter = new FakeAdapter();
        invalidAdapter.createResponse = unknown("payment-invalid-query");
        PaymentService invalidService = service(invalidAdapter);
        PaymentIntent invalidIntent = invalidService.create(
                createCommand("safe-create-query-invalid-0001", "order-query-invalid"));
        invalidService.confirm(
                confirmation(invalidIntent, "safe-confirm-query-invalid-0001"));
        invalidAdapter.queryResponse = new ProviderPayment("request-invalid-query",
                "payment-invalid-query", ProviderOutcome.SUCCEEDED,
                Money.of(1_000, "USD"), null, true, Map.of());

        PaymentCoreException invalid = assertThrows(PaymentCoreException.class,
                () -> invalidService.resolveUnknown(TENANT, invalidIntent.id(),
                        "correlation-invalid-query"));
        assertEquals("PROVIDER_AMOUNT_MISSING", invalid.code());
        assertEquals(List.of(AttemptState.UNKNOWN, AttemptState.UNKNOWN),
                invalidService.attempts(TENANT, invalidIntent.id()).stream()
                        .map(PaymentAttempt::state).toList());
        invalidAdapter.queryResponse = success("payment-invalid-query");
        assertEquals(IntentState.CAPTURED, invalidService.resolveUnknown(TENANT,
                invalidIntent.id(), "correlation-valid-query-retry").intent().state());
        assertEquals(List.of(AttemptState.SUCCEEDED, AttemptState.UNKNOWN,
                        AttemptState.SUCCEEDED),
                invalidService.attempts(TENANT, invalidIntent.id()).stream()
                        .map(PaymentAttempt::state).toList());

        FakeAdapter failedAdapter = new FakeAdapter();
        failedAdapter.createResponse = unknown("payment-failed-query");
        PaymentService failedService = service(failedAdapter);
        PaymentIntent failedIntent = failedService.create(
                createCommand("safe-create-query-failed-0001", "order-query-failed"));
        failedService.confirm(
                confirmation(failedIntent, "safe-confirm-query-failed-0001"));
        failedAdapter.queryException = new ProviderException("QUERY_UNAVAILABLE",
                "query transport failed before an outcome", true, false);

        failedService.resolveUnknown(TENANT, failedIntent.id(), "correlation-failed-query");
        assertEquals(List.of(AttemptState.UNKNOWN, AttemptState.FAILED),
                failedService.attempts(TENANT, failedIntent.id()).stream()
                        .map(PaymentAttempt::state).toList());
    }

    @Test
    void directCancelUsesDurablePayloadBoundActionReceipt() {
        InMemoryPaymentRepository repository = new InMemoryPaymentRepository();
        FakeAdapter adapter = new FakeAdapter();
        PaymentService firstProcess = service(adapter, repository);
        PaymentIntent intent = firstProcess.create(
                createCommand("safe-create-cancel-key-0001", "order-cancel"));
        IntentActionCommand command = new IntentActionCommand(TENANT, intent.id(),
                "safe-direct-cancel-key-0001", "correlation-cancel", "customer_request");
        PaymentIntent canceled = firstProcess.cancel(command);

        PaymentService restartedProcess = service(adapter, repository);
        PaymentIntent replay = restartedProcess.cancel(command);
        PaymentCoreException changedPayload = assertThrows(PaymentCoreException.class,
                () -> restartedProcess.cancel(new IntentActionCommand(TENANT, intent.id(),
                        command.idempotencyKey(), "correlation-cancel-retry", "fraud_review")));
        PaymentCoreException newKeyAfterCompletion = assertThrows(PaymentCoreException.class,
                () -> restartedProcess.cancel(new IntentActionCommand(TENANT, intent.id(),
                        "safe-direct-cancel-key-0002", "correlation-cancel-new-key",
                        "customer_request")));

        assertEquals(IntentState.CANCELED, replay.state());
        assertEquals(canceled.version(), replay.version());
        assertEquals("IDEMPOTENCY_KEY_REUSE", changedPayload.code());
        assertEquals("CANCEL_NOT_ALLOWED", newKeyAfterCompletion.code());
        assertEquals(true, repository.findActionReceipt(TENANT, intent.id(),
                command.idempotencyKey()).isPresent());
    }

    private static PaymentService service(FakeAdapter adapter) {
        return service(adapter, new InMemoryPaymentRepository());
    }

    private static PaymentService service(FakeAdapter adapter, PaymentRepository repository) {
        ProviderAccount account = account();
        ProviderRoute route = new ProviderRoute(account, new ProviderCapability(
                "stripe", "card", Set.of("USD"), Set.of("US"), true, true, true, true),
                1, "test-v1");
        MerchantConfigurationRepository configuration = new MerchantConfigurationRepository() {
            @Override
            public Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId,
                    UUID accountId) {
                return TENANT.equals(tenantId) && PROJECT.equals(projectId)
                        && ACCOUNT_ID.equals(accountId) ? Optional.of(account) : Optional.empty();
            }

            @Override
            public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
                return List.of(route);
            }
        };
        return new PaymentService(repository, configuration,
                new RoutingService(configuration), new ProviderAdapterRegistry(List.of(adapter)), CLOCK);
    }

    private static ProviderAccount account() {
        return new ProviderAccount(ACCOUNT_ID, TENANT, PROJECT, MERCHANT, "stripe", "sandbox",
                "merchant-test", SecretReference.parse("vault://payment/test"), "v1",
                AccountStatus.ACTIVE);
    }

    private static CreateIntentCommand createCommand(String key, String order) {
        return createCommand(key, order, Duration.ofHours(1));
    }

    private static CreateIntentCommand createCommand(String key, String order, Duration timeToLive) {
        return new CreateIntentCommand(TENANT, PROJECT, MERCHANT, order, Money.of(1_000, "USD"),
                Set.of("card"), ConfirmationMode.AUTOMATIC, "US", timeToLive, key);
    }

    private static ConfirmationCommand confirmation(PaymentIntent intent, String key) {
        return new ConfirmationCommand(TENANT, intent.id(), PaymentMethodReference.parse(
                "card", "psp://payment-method/test-reference", "fp-test"), key,
                "correlation-test", "checkout-complete", Map.of());
    }

    private static ProviderPayment authorized(String providerPaymentId) {
        return new ProviderPayment("request-authorized", providerPaymentId,
                ProviderOutcome.AUTHORIZED, Money.of(1_000, "USD"), null, true, Map.of());
    }

    private static ProviderPayment unknown(String providerPaymentId) {
        return new ProviderPayment("request-unknown", providerPaymentId,
                ProviderOutcome.UNKNOWN, null, null, false, Map.of());
    }

    private static ProviderPayment success(String providerPaymentId) {
        Money amount = Money.of(1_000, "USD");
        return new ProviderPayment("request-query", providerPaymentId,
                ProviderOutcome.SUCCEEDED, amount, amount, true, Map.of());
    }

    private static void assertConfirmationRejected(ProviderPayment response, String expectedCode,
            String suffix) {
        FakeAdapter adapter = new FakeAdapter();
        adapter.createResponse = response;
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(createCommand("safe-create-reject-" + suffix,
                "order-reject-" + suffix));

        PaymentCoreException exception = assertThrows(PaymentCoreException.class,
                () -> service.confirm(confirmation(intent, "safe-confirm-reject-" + suffix)));

        assertEquals(expectedCode, exception.code());
        assertEquals(IntentState.CREATED, service.get(TENANT, intent.id()).state());
    }

    private static void assertCaptureRejected(ProviderPayment response, String expectedCode,
            String suffix) {
        FakeAdapter adapter = new FakeAdapter();
        adapter.createResponse = authorized("provider-payment-" + suffix);
        PaymentService service = service(adapter);
        PaymentIntent intent = service.create(createCommand("safe-create-reject-" + suffix,
                "order-reject-" + suffix));
        service.confirm(confirmation(intent, "safe-confirm-authorize-" + suffix));
        adapter.captureResponse = response;

        PaymentCoreException exception = assertThrows(PaymentCoreException.class,
                () -> service.capture(new CaptureCommand(TENANT, intent.id(), 400,
                        "safe-capture-reject-" + suffix, "correlation-capture-" + suffix)));

        assertEquals(expectedCode, exception.code());
        assertEquals(IntentState.AUTHORIZED, service.get(TENANT, intent.id()).state());
        assertEquals(0, service.get(TENANT, intent.id()).capturedAmountMinor());
    }

    private static final class FakeAdapter implements ProviderAdapter {
        private final AtomicInteger calls = new AtomicInteger();
        private final AtomicInteger captureCalls = new AtomicInteger();
        private final CountDownLatch release = new CountDownLatch(1);
        private volatile boolean block;
        private volatile ProviderPayment createResponse;
        private volatile ProviderPayment captureResponse;
        private volatile ProviderPayment queryResponse;
        private volatile ProviderException queryException;

        @Override
        public String provider() {
            return "stripe";
        }

        @Override
        public ProviderPayment createPayment(CreatePaymentCommand command) {
            calls.incrementAndGet();
            if (block) {
                try {
                    release.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(exception);
                }
            }
            return createResponse != null ? createResponse : new ProviderPayment(
                    "request-1", "provider-payment-1",
                    ProviderOutcome.SUCCEEDED, command.amount(), command.amount(), true, Map.of());
        }

        @Override
        public ProviderPayment queryPayment(ProviderRequestContext context,
                String providerPaymentId, String businessOrderNo) {
            if (queryException != null) {
                throw queryException;
            }
            return queryResponse != null ? queryResponse : success("provider-payment-1");
        }

        @Override
        public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId,
                Money amount) {
            captureCalls.incrementAndGet();
            return captureResponse != null ? captureResponse : new ProviderPayment(
                    "request-capture", providerPaymentId,
                    ProviderOutcome.SUCCEEDED, amount, amount, true, Map.of());
        }

        @Override
        public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId,
                String reason) {
            return new ProviderPayment("request-cancel", providerPaymentId,
                    ProviderOutcome.CANCELED, null, null, true, Map.of());
        }

        @Override
        public ProviderRefund refund(RefundCommand command) {
            return new ProviderRefund("refund-1", ProviderOutcome.SUCCEEDED, command.amount(), true);
        }

        @Override
        public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
                String refundReference) {
            return new ProviderRefund(providerRefundId, ProviderOutcome.UNKNOWN, null, false);
        }

        @Override
        public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            throw new UnsupportedOperationException("not used by this payment-core test");
        }

    }
}
