package com.elmpay.payment.provider;

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
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class AccountAwareProviderAdapterFactoryTest {
    @Test
    void resolvesEveryCallByTenantAccountAndExactCredentialVersion() {
        ProviderAccount first = account(UUID.randomUUID(), UUID.randomUUID(), "credential-v1");
        ProviderAccount second = account(UUID.randomUUID(), UUID.randomUUID(), "credential-v2");
        FakeAccounts accounts = new FakeAccounts(first, second);
        FakeCredentials credentials = new FakeCredentials(true);
        RecordingBreaker breaker = new RecordingBreaker();
        List<UUID> constructedFor = new ArrayList<>();
        ProviderAdapter adapter = new AccountAwareProviderAdapterFactory(accounts, credentials,
                List.of(factory(constructedFor)), breaker, List.of(
                        binding(first), binding(second))).createAdapters().getFirst();

        assertEquals("pay-" + first.id(), adapter.queryPayment(context(first), "pay-1", "order-1")
                .providerPaymentId());
        assertEquals("pay-" + second.id(), adapter.queryPayment(context(second), "pay-2", "order-2")
                .providerPaymentId());
        assertEquals(List.of(first.id(), second.id()), constructedFor);
        assertEquals(List.of(key(first), key(second)), credentials.resolved);
        assertEquals(2, credentials.closed.get());
        assertTrue(adapter.configured());
        assertEquals(4, credentials.closed.get(), "readiness leases must also be closed");
        assertEquals(List.of(ProviderCallCircuitBreaker.Operation.QUERY_PAYMENT,
                ProviderCallCircuitBreaker.Operation.QUERY_PAYMENT), breaker.operations);
    }

    @Test
    void rejectsCrossTenantAndStaleVersionBeforeResolvingASecret() {
        ProviderAccount account = account(UUID.randomUUID(), UUID.randomUUID(), "credential-v3");
        FakeCredentials credentials = new FakeCredentials(true);
        ProviderAdapter adapter = new AccountAwareProviderAdapterFactory(new FakeAccounts(account),
                credentials, List.of(factory(new ArrayList<>())), new RecordingBreaker(),
                List.of(binding(account)))
                .createAdapters().getFirst();

        ProviderRequestContext crossTenant = new ProviderRequestContext(UUID.randomUUID(),
                account.projectId(), account.id(), "idempotency-key-00001", "correlation-1",
                account.credentialVersion());
        ProviderException missing = assertThrows(ProviderException.class,
                () -> adapter.queryPayment(crossTenant, "pay-1", "order-1"));
        assertEquals("PROVIDER_ACCOUNT_NOT_FOUND", missing.code());

        ProviderRequestContext stale = new ProviderRequestContext(account.tenantId(),
                account.projectId(), account.id(), "idempotency-key-00002", "correlation-2",
                "credential-old");
        ProviderException mismatch = assertThrows(ProviderException.class,
                () -> adapter.queryPayment(stale, "pay-1", "order-1"));
        assertEquals("PROVIDER_CREDENTIAL_VERSION_MISMATCH", mismatch.code());
        assertTrue(credentials.resolved.isEmpty());
    }

    @Test
    void readinessAndWebhookResolutionFailClosed() {
        ProviderAccount account = account(UUID.randomUUID(), UUID.randomUUID(), "credential-v4");
        FakeCredentials unavailable = new FakeCredentials(false);
        ProviderAdapter notReady = new AccountAwareProviderAdapterFactory(new FakeAccounts(account),
                unavailable, List.of(factory(new ArrayList<>())), new RecordingBreaker(),
                List.of(binding(account)))
                .createAdapters().getFirst();
        assertFalse(notReady.configured());

        FakeCredentials available = new FakeCredentials(true);
        ProviderAdapter noDeclaredAccounts = new AccountAwareProviderAdapterFactory(
                new FakeAccounts(account), available, List.of(factory(new ArrayList<>())),
                new RecordingBreaker(), List.of()).createAdapters().getFirst();
        assertFalse(noDeclaredAccounts.configured());

        RecordingBreaker breaker = new RecordingBreaker();
        ProviderAdapter ready = new AccountAwareProviderAdapterFactory(new FakeAccounts(account),
                available, List.of(factory(new ArrayList<>())), breaker, List.of(binding(account)))
                .createAdapters().getFirst();
        VerifiedProviderEvent event = ready.verifyWebhook(new WebhookRequest(account.tenantId(),
                account.id(), Map.of("signature", "opaque"), "{}".getBytes(), Instant.EPOCH));
        assertEquals(account.id(), event.merchantAccountId());
        assertEquals(List.of(ProviderCallCircuitBreaker.Operation.VERIFY_WEBHOOK),
                breaker.operations);

        WebhookRequest crossTenant = new WebhookRequest(UUID.randomUUID(), account.id(),
                Map.of("signature", "opaque"), "{}".getBytes(), Instant.EPOCH);
        assertEquals("PROVIDER_ACCOUNT_NOT_FOUND", assertThrows(ProviderException.class,
                () -> ready.verifyWebhook(crossTenant)).code());
    }

    @Test
    void everyProviderOperationUsesTheSameAccountScopedBreakerBeforeDispatch() {
        ProviderAccount account = account(UUID.randomUUID(), UUID.randomUUID(), "credential-v5");
        FakeCredentials credentials = new FakeCredentials(true);
        RecordingBreaker breaker = new RecordingBreaker();
        ProviderAdapter adapter = new AccountAwareProviderAdapterFactory(new FakeAccounts(account),
                credentials, List.of(factory(new ArrayList<>())), breaker,
                List.of(binding(account))).createAdapters().getFirst();
        ProviderRequestContext context = context(account);

        adapter.createPayment(new CreatePaymentCommand(context, UUID.randomUUID(), "order-1",
                Money.of(100, "USD"), "card", null, Map.of()));
        adapter.queryPayment(context, "pay-1", "order-1");
        adapter.capture(context, "pay-1", Money.of(100, "USD"));
        adapter.cancel(context, "pay-1", "requested");
        adapter.refund(new RefundCommand(context, UUID.randomUUID(), "pay-1",
                Money.of(100, "USD"), "requested"));
        adapter.queryRefund(context, "refund-1", "refund-reference-1");
        adapter.verifyWebhook(new WebhookRequest(account.tenantId(), account.id(),
                Map.of("signature", "opaque"), "{}".getBytes(), Instant.EPOCH));

        assertEquals(List.of(
                ProviderCallCircuitBreaker.Operation.CREATE_PAYMENT,
                ProviderCallCircuitBreaker.Operation.QUERY_PAYMENT,
                ProviderCallCircuitBreaker.Operation.CAPTURE,
                ProviderCallCircuitBreaker.Operation.CANCEL,
                ProviderCallCircuitBreaker.Operation.REFUND,
                ProviderCallCircuitBreaker.Operation.QUERY_REFUND,
                ProviderCallCircuitBreaker.Operation.VERIFY_WEBHOOK), breaker.operations);
        assertEquals(7, breaker.scopes.size());
        assertTrue(breaker.scopes.stream().allMatch(scope -> scope.equals(
                account.tenantId() + ":" + account.id() + ":stripe")));
        assertEquals(7, credentials.closed.get());
    }

    private static ProviderAccountAdapterFactory factory(List<UUID> constructedFor) {
        return new ProviderAccountAdapterFactory() {
            @Override public String provider() { return "stripe"; }
            @Override public ProviderRuntimeAdapter create(ProviderAccount account,
                    ProviderCredential credential) {
                constructedFor.add(account.id());
                return new ScopedProviderRuntimeAdapter(new StubAdapter(account));
            }
        };
    }

    private static ProviderAccount account(UUID tenantId, UUID accountId, String version) {
        return new ProviderAccount(accountId, tenantId, UUID.randomUUID(), UUID.randomUUID(),
                "stripe", "production", "acct_" + accountId,
                SecretReference.parse("vault://payments/" + accountId), version,
                AccountStatus.ACTIVE);
    }

    private static ProviderReadinessBinding binding(ProviderAccount account) {
        return new ProviderReadinessBinding(account.provider(), account.tenantId(),
                account.projectId(), account.id());
    }

    private static ProviderRequestContext context(ProviderAccount account) {
        return new ProviderRequestContext(account.tenantId(), account.projectId(), account.id(),
                "idempotency-key-00001", "correlation-1", account.credentialVersion());
    }

    private static String key(ProviderAccount account) {
        return account.tenantId() + ":" + account.id() + ":" + account.credentialVersion();
    }

    private static final class FakeAccounts implements MerchantConfigurationRepository {
        private final Map<UUID, ProviderAccount> values = new LinkedHashMap<>();

        private FakeAccounts(ProviderAccount... accounts) {
            for (ProviderAccount account : accounts) values.put(account.id(), account);
        }

        @Override public Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId,
                UUID accountId) {
            return findAccount(tenantId, accountId).filter(value -> value.projectId().equals(projectId));
        }

        @Override public Optional<ProviderAccount> findAccount(UUID tenantId, UUID accountId) {
            return Optional.ofNullable(values.get(accountId))
                    .filter(value -> value.tenantId().equals(tenantId));
        }

        @Override public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
            return List.of();
        }
    }

    private static final class FakeCredentials implements ProviderCredentialResolver {
        private final boolean configured;
        private final List<String> resolved = new ArrayList<>();
        private final AtomicInteger closed = new AtomicInteger();

        private FakeCredentials(boolean configured) { this.configured = configured; }
        @Override public boolean configured() { return configured; }
        @Override public ProviderCredential resolve(UUID tenantId, UUID providerAccountId,
                SecretReference reference, String credentialVersion) {
            resolved.add(tenantId + ":" + providerAccountId + ":" + credentialVersion);
            return new ProviderCredential() {
                @Override public String version() { return credentialVersion; }
                @Override public void close() { closed.incrementAndGet(); }
            };
        }
    }

    private static final class RecordingBreaker implements ProviderCallCircuitBreaker {
        private final List<Operation> operations = new ArrayList<>();
        private final List<String> scopes = new ArrayList<>();

        @Override
        public <T> T execute(UUID tenantId, UUID providerAccountId, String provider,
                Operation operation, ProviderCall<T> call) {
            operations.add(operation);
            scopes.add(tenantId + ":" + providerAccountId + ":" + provider);
            return call.invoke();
        }
    }

    private record StubAdapter(ProviderAccount account) implements ProviderAdapter {
        @Override public String provider() { return account.provider(); }
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) {
            return payment();
        }
        @Override public ProviderPayment queryPayment(ProviderRequestContext context, String id,
                String order) { return payment(); }
        @Override public ProviderPayment capture(ProviderRequestContext context, String id,
                Money amount) { return payment(); }
        @Override public ProviderPayment cancel(ProviderRequestContext context, String id,
                String reason) { return payment(); }
        @Override public ProviderRefund refund(RefundCommand command) {
            return new ProviderRefund("refund-" + account.id(), ProviderOutcome.UNKNOWN, null,
                    false);
        }
        @Override public ProviderRefund queryRefund(ProviderRequestContext context, String id,
                String reference) { return refund(new RefundCommand(context, UUID.randomUUID(),
                        id, Money.of(1, "USD"), "query")); }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            return new VerifiedProviderEvent(request.tenantId(), request.merchantAccountId(),
                    "event-1", "payment.updated", "pay-1", "order-1", Money.of(1, "USD"),
                    "key-1", request.receivedAt(), Map.of());
        }
        private ProviderPayment payment() {
            return new ProviderPayment("request-1", "pay-" + account.id(),
                    ProviderOutcome.UNKNOWN, null, null, false, Map.of());
        }
    }
}
