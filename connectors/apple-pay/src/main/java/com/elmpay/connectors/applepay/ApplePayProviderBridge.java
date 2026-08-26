package com.elmpay.connectors.applepay;

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
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * ServiceLoader bridge for the safe Apple Pay pre-token phase. Opaque payment tokens must be
 * forwarded through {@link ApplePayAdapter#forward} and never serialized into common commands.
 */
public final class ApplePayProviderBridge implements ProviderAdapter {
    private static final String PROVIDER = "apple_pay";
    private static final String PROPERTY = "elmpay.applePay.adapterFactory";
    private static final String ENVIRONMENT = "ELMPAY_APPLE_PAY_ADAPTER_FACTORY";
    private final ProviderAdapter delegate;

    public record Runtime(ApplePayAdapter adapter, Clock clock) {
        public Runtime {
            Objects.requireNonNull(adapter, "adapter");
            Objects.requireNonNull(clock, "clock");
        }
    }

    public ApplePayProviderBridge() { this(load()); }
    public ApplePayProviderBridge(ProviderAdapter delegate) { this.delegate = requireProvider(delegate); }
    public ApplePayProviderBridge(Runtime runtime) { this.delegate = new StrongDelegate(runtime); }
    @Override public String provider() { return PROVIDER; }
    @Override public boolean configured() { return delegate.configured(); }
    @Override public ProviderPayment createPayment(CreatePaymentCommand command) { return delegate.createPayment(command); }
    @Override public ProviderPayment queryPayment(ProviderRequestContext context, String providerPaymentId,
            String businessOrderNo) { return delegate.queryPayment(context, providerPaymentId, businessOrderNo); }
    @Override public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId,
            Money amount) { return delegate.capture(context, providerPaymentId, amount); }
    @Override public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId,
            String reason) { return delegate.cancel(context, providerPaymentId, reason); }
    @Override public ProviderRefund refund(RefundCommand command) { return delegate.refund(command); }
    @Override public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
            String refundReference) { return delegate.queryRefund(context, providerRefundId, refundReference); }
    @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) { return delegate.verifyWebhook(request); }

    private static ProviderAdapter load() {
        String name = System.getProperty(PROPERTY);
        if (name == null || name.isBlank()) name = System.getenv(ENVIRONMENT);
        if (name == null || name.isBlank()) return new MissingDelegate("PROVIDER_CONFIG_MISSING");
        try {
            Object factory = Class.forName(name, true, Thread.currentThread().getContextClassLoader())
                    .getConstructor().newInstance();
            if (!(factory instanceof Supplier<?> supplier)) {
                throw new IllegalStateException("configured Apple Pay factory must implement Supplier");
            }
            Object supplied = supplier.get();
            if (supplied instanceof Runtime runtime) return new StrongDelegate(runtime);
            if (supplied instanceof ProviderAdapter adapter) return requireProvider(adapter);
            throw new IllegalStateException("configured Apple Pay factory returned an invalid adapter");
        } catch (ReflectiveOperationException | RuntimeException exception) {
            return new MissingDelegate("PROVIDER_CONFIG_INVALID");
        }
    }

    private static ProviderAdapter requireProvider(ProviderAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        if (!PROVIDER.equals(adapter.provider()) || adapter instanceof ApplePayProviderBridge) {
            throw new IllegalArgumentException("Apple Pay bridge requires a non-bridge Apple Pay adapter");
        }
        return adapter;
    }

    private static final class StrongDelegate implements ProviderAdapter {
        private final Runtime runtime;
        StrongDelegate(Runtime runtime) { this.runtime = Objects.requireNonNull(runtime, "runtime"); }
        @Override public String provider() { return PROVIDER; }

        @Override
        public ProviderPayment createPayment(CreatePaymentCommand command) {
            if (!"apple_pay".equals(command.method())) throw failure("PAYMENT_METHOD_UNSUPPORTED");
            rejectSensitiveParameters(command.providerParameters());
            String domain = required(command.providerParameters(), "domain");
            String walletValue = required(command.providerParameters(), "device_has_wallet");
            if (!"true".equals(walletValue) && !"false".equals(walletValue)) {
                throw failure("DEVICE_CAPABILITY_INVALID");
            }
            String psp = required(command.providerParameters(), "psp").toLowerCase(Locale.ROOT);
            if (!psp.equals("stripe") && !psp.equals("paypal")) throw failure("PSP_UNSUPPORTED");
            Instant now = Instant.now(runtime.clock());
            ApplePayAdapter.Capability capability = runtime.adapter().capability(
                    command.context().tenantId().toString(), command.context().merchantAccountId().toString(),
                    domain, Boolean.parseBoolean(walletValue),
                    command.providerParameters().get("merchant_token_reference"), now);
            String session = "apple_session_" + command.paymentIntentId();
            if (capability == ApplePayAdapter.Capability.AVAILABLE) {
                return new ProviderPayment(command.context().idempotencyKey(), session,
                        ProviderOutcome.REQUIRES_ACTION, null, null, false,
                        Map.of("action", "collect_apple_pay_token", "psp", psp, "domain", domain));
            }
            if (capability == ApplePayAdapter.Capability.NO_WALLET) {
                return new ProviderPayment(command.context().idempotencyKey(), session,
                        ProviderOutcome.FAILED, null, null, true,
                        Map.of("action", "fallback_required", "reason", "NO_WALLET"));
            }
            throw failure("APPLE_PAY_" + capability.name());
        }

        @Override public ProviderPayment queryPayment(ProviderRequestContext c, String id, String order) {
            throw failure("QUERY_OWNED_BY_PSP");
        }
        @Override public ProviderPayment capture(ProviderRequestContext c, String id, Money amount) {
            throw failure("CAPTURE_OWNED_BY_PSP");
        }
        @Override public ProviderPayment cancel(ProviderRequestContext c, String id, String reason) {
            throw failure("CANCEL_OWNED_BY_PSP");
        }
        @Override public ProviderRefund refund(RefundCommand command) { throw failure("REFUND_OWNED_BY_PSP"); }
        @Override public ProviderRefund queryRefund(ProviderRequestContext c, String id, String ref) {
            throw failure("REFUND_QUERY_OWNED_BY_PSP");
        }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            throw failure("WEBHOOK_OWNED_BY_PSP");
        }
    }

    private static final class MissingDelegate implements ProviderAdapter {
        private final String code;
        MissingDelegate(String code) { this.code = code; }
        @Override public String provider() { return PROVIDER; }
        @Override public boolean configured() { return false; }
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) { throw missing(); }
        @Override public ProviderPayment queryPayment(ProviderRequestContext c, String id, String order) { throw missing(); }
        @Override public ProviderPayment capture(ProviderRequestContext c, String id, Money amount) { throw missing(); }
        @Override public ProviderPayment cancel(ProviderRequestContext c, String id, String reason) { throw missing(); }
        @Override public ProviderRefund refund(RefundCommand command) { throw missing(); }
        @Override public ProviderRefund queryRefund(ProviderRequestContext c, String id, String ref) { throw missing(); }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) { throw missing(); }
        private ProviderException missing() {
            return new ProviderException(code, "Apple Pay provider is not configured", false, false);
        }
    }

    private static String required(Map<String, String> parameters, String key) {
        String value = parameters.get(key);
        if (value == null || value.isBlank()) throw failure("PROVIDER_PARAMETER_REQUIRED");
        return value;
    }

    private static void rejectSensitiveParameters(Map<String, String> parameters) {
        for (String key : parameters.keySet()) {
            String normalized = key.toLowerCase(Locale.ROOT).replace("-", "_");
            if (normalized.contains("token") && !normalized.equals("merchant_token_reference")
                    || normalized.matches(".*(pan|cvv|cvc|card_number|track1|track2).*$")) {
                throw failure("RAW_PAYMENT_CREDENTIAL_FORBIDDEN");
            }
        }
    }

    private static ProviderException failure(String code) {
        return new ProviderException(code, "Apple Pay request cannot be handled by this bridge", false, false);
    }
}
