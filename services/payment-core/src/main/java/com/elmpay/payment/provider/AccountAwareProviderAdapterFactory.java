package com.elmpay.payment.provider;

import com.elmpay.merchant.AccountStatus;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Constructs provider ports that resolve account and credential version for every operation.
 * No process-global provider credential or singleton merchant adapter is retained.
 */
public final class AccountAwareProviderAdapterFactory {
    private final MerchantConfigurationRepository accounts;
    private final ProviderCredentialResolver credentials;
    private final Map<String, ProviderAccountAdapterFactory> factories;
    private final ProviderCallCircuitBreaker circuitBreaker;
    private final List<ProviderReadinessBinding> readinessBindings;

    public AccountAwareProviderAdapterFactory(MerchantConfigurationRepository accounts,
            ProviderCredentialResolver credentials, List<ProviderAccountAdapterFactory> factories,
            ProviderCallCircuitBreaker circuitBreaker,
            List<ProviderReadinessBinding> readinessBindings) {
        this.accounts = Objects.requireNonNull(accounts, "accounts");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        Objects.requireNonNull(factories, "factories");
        Map<String, ProviderAccountAdapterFactory> indexed = new HashMap<>();
        for (ProviderAccountAdapterFactory factory : factories) {
            String provider = normalizeProvider(factory.provider());
            if (indexed.putIfAbsent(provider, factory) != null) {
                throw new IllegalArgumentException("duplicate account adapter factory: " + provider);
            }
        }
        this.factories = Map.copyOf(indexed);
        this.circuitBreaker = Objects.requireNonNull(circuitBreaker, "circuitBreaker");
        this.readinessBindings = List.copyOf(readinessBindings);
    }

    public List<ProviderAdapter> createAdapters() {
        return factories.keySet().stream().sorted().map(AccountAwareAdapter::new)
                .map(ProviderAdapter.class::cast).toList();
    }

    private final class AccountAwareAdapter implements ProviderAdapter {
        private final String provider;

        private AccountAwareAdapter(String provider) {
            this.provider = provider;
        }

        @Override
        public String provider() {
            return provider;
        }

        @Override
        public boolean configured() {
            if (!credentials.configured()) {
                return false;
            }
            List<ProviderReadinessBinding> bindings = readinessBindings.stream()
                    .filter(binding -> provider.equals(binding.provider())).toList();
            if (bindings.isEmpty()) {
                return false;
            }
            try {
                for (ProviderReadinessBinding binding : bindings) {
                    ProviderAccount account = accounts.findAccount(binding.tenantId(),
                            binding.projectId(), binding.providerAccountId()).orElse(null);
                    if (account == null || account.status() != AccountStatus.ACTIVE
                            || !provider.equals(account.provider())) {
                        return false;
                    }
                    if (!withDelegate(account, null, ProviderAdapter::configured)) {
                        return false;
                    }
                }
                return true;
            } catch (RuntimeException exception) {
                return false;
            }
        }

        @Override
        public ProviderPayment createPayment(CreatePaymentCommand command) {
            ProviderAccount account = require(command.context(), true, false);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.CREATE_PAYMENT,
                    adapter -> adapter.createPayment(command));
        }

        @Override
        public ProviderPayment queryPayment(ProviderRequestContext context,
                String providerPaymentId, String businessOrderNo) {
            ProviderAccount account = require(context, false, false);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.QUERY_PAYMENT,
                    adapter -> adapter.queryPayment(context, providerPaymentId, businessOrderNo));
        }

        @Override
        public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId,
                Money amount) {
            ProviderAccount account = require(context, true, false);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.CAPTURE,
                    adapter -> adapter.capture(context, providerPaymentId, amount));
        }

        @Override
        public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId,
                String reason) {
            ProviderAccount account = require(context, false, false);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.CANCEL,
                    adapter -> adapter.cancel(context, providerPaymentId, reason));
        }

        @Override
        public ProviderRefund refund(RefundCommand command) {
            ProviderAccount account = require(command.context(), false, true);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.REFUND,
                    adapter -> adapter.refund(command));
        }

        @Override
        public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
                String refundReference) {
            ProviderAccount account = require(context, false, true);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.QUERY_REFUND,
                    adapter -> adapter.queryRefund(context, providerRefundId, refundReference));
        }

        @Override
        public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            ProviderAccount account = accounts.findAccount(request.tenantId(),
                    request.merchantAccountId()).orElseThrow(() -> failure(
                            "PROVIDER_ACCOUNT_NOT_FOUND", "provider account is not available"));
            validateProviderAndStatus(account, false, false);
            return withDelegate(account, ProviderCallCircuitBreaker.Operation.VERIFY_WEBHOOK,
                    adapter -> adapter.verifyWebhook(request));
        }

        private ProviderAccount require(ProviderRequestContext context, boolean newMoneyMovement,
                boolean refund) {
            ProviderAccount account = accounts.findAccount(context.tenantId(), context.projectId(),
                    context.merchantAccountId()).orElseThrow(() -> failure(
                            "PROVIDER_ACCOUNT_NOT_FOUND", "provider account is not available"));
            if (!constantEquals(account.credentialVersion(), context.credentialVersion())) {
                throw failure("PROVIDER_CREDENTIAL_VERSION_MISMATCH",
                        "provider credential version is not current");
            }
            validateProviderAndStatus(account, newMoneyMovement, refund);
            return account;
        }

        private void validateProviderAndStatus(ProviderAccount account, boolean newMoneyMovement,
                boolean refund) {
            if (!provider.equals(account.provider())) {
                throw failure("PROVIDER_ACCOUNT_MISMATCH",
                        "provider account does not belong to this provider");
            }
            boolean permitted = newMoneyMovement ? account.status().permitsNewPayments()
                    : refund ? account.status().permitsRefunds()
                    : account.status() == AccountStatus.ACTIVE
                            || account.status() == AccountStatus.SUSPENDED;
            if (!permitted) {
                throw failure("PROVIDER_ACCOUNT_INACTIVE", "provider account is not active");
            }
        }

        private <T> T withDelegate(ProviderAccount account,
                ProviderCallCircuitBreaker.Operation breakerOperation,
                AdapterOperation<T> operation) {
            if (breakerOperation == null) {
                return withResolvedDelegate(account, operation);
            }
            return circuitBreaker.execute(account.tenantId(), account.id(), provider,
                    breakerOperation, () -> withResolvedDelegate(account, operation));
        }

        private <T> T withResolvedDelegate(ProviderAccount account, AdapterOperation<T> operation) {
            ProviderCredential credential;
            try {
                credential = credentials.resolve(account.tenantId(), account.id(),
                        account.credentialReference(), account.credentialVersion());
            } catch (RuntimeException exception) {
                throw failure("PROVIDER_CREDENTIAL_UNAVAILABLE",
                        "provider credential is unavailable");
            }
            if (credential == null) {
                throw failure("PROVIDER_CREDENTIAL_UNAVAILABLE",
                        "provider credential is unavailable");
            }
            try (credential) {
                if (!constantEquals(account.credentialVersion(), credential.version())) {
                    throw failure("PROVIDER_CREDENTIAL_VERSION_MISMATCH",
                            "resolved provider credential version is incorrect");
                }
                ProviderRuntimeAdapter delegate;
                try {
                    delegate = factories.get(provider).create(account, credential);
                } catch (RuntimeException exception) {
                    throw failure("PROVIDER_RUNTIME_NOT_READY",
                            "account-bound provider runtime is not ready");
                }
                if (delegate == null || !provider.equals(normalizeProvider(delegate.provider()))
                        || !delegate.configured()) {
                    throw failure("PROVIDER_RUNTIME_NOT_READY",
                            "account-bound provider runtime is not ready");
                }
                try (delegate) {
                    return operation.apply(delegate);
                } catch (ProviderException exception) {
                    throw exception;
                } catch (RuntimeException exception) {
                    throw new ProviderException("PROVIDER_RUNTIME_FAILURE",
                            "account-bound provider operation failed", false, true);
                }
            } catch (ProviderException exception) {
                throw exception;
            } catch (RuntimeException exception) {
                throw failure("PROVIDER_CREDENTIAL_UNAVAILABLE",
                        "provider credential lease could not be closed safely");
            }
        }
    }

    @FunctionalInterface
    private interface AdapterOperation<T> {
        T apply(ProviderAdapter adapter);
    }

    private static String normalizeProvider(String provider) {
        String value = Objects.requireNonNull(provider, "provider").toLowerCase(Locale.ROOT);
        if (!value.matches("[a-z][a-z0-9_]{1,31}")) {
            throw new IllegalArgumentException("provider has an invalid format");
        }
        return value;
    }

    private static boolean constantEquals(String first, String second) {
        if (first == null || second == null) {
            return false;
        }
        return MessageDigest.isEqual(first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
    }

    private static ProviderException failure(String code, String message) {
        return new ProviderException(code, message, false, false);
    }
}
