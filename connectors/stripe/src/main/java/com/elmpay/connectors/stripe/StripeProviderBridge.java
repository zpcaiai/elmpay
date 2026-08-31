package com.elmpay.connectors.stripe;

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
import java.util.Objects;
import java.util.Map;
import java.time.Instant;
import java.util.function.Supplier;

/** ServiceLoader bridge whose external factory supplies the secret-manager-configured adapter. */
public final class StripeProviderBridge implements ProviderAdapter {
    private static final String PROVIDER = "stripe";
    private static final String PROPERTY = "elmpay.stripe.adapterFactory";
    private static final String ENVIRONMENT = "ELMPAY_STRIPE_ADAPTER_FACTORY";
    private final ProviderAdapter delegate;

    @FunctionalInterface public interface WebhookExpectationResolver {
        StripeAdapter.ExpectedWebhook resolve(WebhookRequest request);
    }
    public record Runtime(StripeAdapter adapter, WebhookExpectationResolver webhookExpectations) {
        public Runtime {
            Objects.requireNonNull(adapter, "adapter");
            Objects.requireNonNull(webhookExpectations, "webhookExpectations");
        }
    }

    public StripeProviderBridge() { this(load()); }
    public StripeProviderBridge(ProviderAdapter delegate) { this.delegate = requireProvider(delegate); }
    public StripeProviderBridge(Runtime runtime) { this.delegate = new StrongDelegate(runtime); }
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
                throw new IllegalStateException("configured Stripe factory must implement Supplier");
            }
            Object supplied = supplier.get();
            if (supplied instanceof Runtime runtime) return new StrongDelegate(runtime);
            if (supplied instanceof ProviderAdapter adapter) return requireProvider(adapter);
            throw new IllegalStateException("configured Stripe factory returned an invalid adapter");
        } catch (ReflectiveOperationException | RuntimeException exception) {
            return new MissingDelegate("PROVIDER_CONFIG_INVALID");
        }
    }

    private static ProviderAdapter requireProvider(ProviderAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        if (!PROVIDER.equals(adapter.provider()) || adapter instanceof StripeProviderBridge) {
            throw new IllegalArgumentException("Stripe bridge requires a non-bridge Stripe adapter");
        }
        return adapter;
    }

    private static final class StrongDelegate implements ProviderAdapter {
        private final Runtime runtime;
        StrongDelegate(Runtime runtime) { this.runtime = Objects.requireNonNull(runtime, "runtime"); }
        @Override public String provider() { return PROVIDER; }
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) {
            if (!"stripe_card".equals(command.method())) throw failure("PAYMENT_METHOD_UNSUPPORTED");
            String paymentMethod = command.providerParameters().get("payment_method_reference");
            StripeAdapter.OperationResult result = runtime.adapter().createPaymentIntent(
                    new StripeAdapter.PaymentRequest(command.amount().amountMinor(),
                            command.amount().currency().code(), paymentMethod,
                            "manual".equals(command.providerParameters().get("capture_method")),
                            command.businessOrderNo(), command.context().idempotencyKey()));
            Map<String, String> action = result.responseBody().isBlank() ? Map.of()
                    : Map.of("provider_action", result.responseBody());
            return payment(command.context(), command.businessOrderNo(), result, command.amount(), action);
        }
        @Override public ProviderPayment queryPayment(ProviderRequestContext context, String id, String order) {
            return payment(context, id, runtime.adapter().queryPaymentIntent(id), null, Map.of());
        }
        @Override public ProviderPayment capture(ProviderRequestContext context, String id, Money amount) {
            return payment(context, id, runtime.adapter().capturePaymentIntent(id, amount.amountMinor(),
                    context.idempotencyKey()), amount, Map.of());
        }
        @Override public ProviderPayment cancel(ProviderRequestContext context, String id, String reason) {
            return payment(context, id, runtime.adapter().cancelPaymentIntent(id, reason,
                    context.idempotencyKey()), null, Map.of());
        }
        @Override public ProviderRefund refund(RefundCommand command) {
            StripeAdapter.OperationResult result = runtime.adapter().refund(command.providerPaymentId(),
                    command.amount().amountMinor(), command.refundId().toString(),
                    command.context().idempotencyKey());
            return refundResult(command.refundId().toString(), result, command.amount());
        }
        @Override public ProviderRefund queryRefund(ProviderRequestContext context, String id, String ref) {
            return refundResult(id, runtime.adapter().queryRefund(id), null);
        }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            String signature = uniqueHeader(request.headers(), "Stripe-Signature");
            StripeAdapter.ExpectedWebhook expected = runtime.webhookExpectations().resolve(request);
            StripeAdapter.VerifiedWebhook event = runtime.adapter().verifyWebhook(signature,
                    request.rawBody(), request.receivedAt(), expected);
            return new VerifiedProviderEvent(request.tenantId(), request.merchantAccountId(), event.eventId(),
                    event.eventType(), event.providerObjectId(), expected.businessOrderNo(), Money.of(expected.amountMinor(),
                            expected.currency()), event.signatureKeyId(), Instant.ofEpochSecond(
                                    event.createdEpochSecond()), Map.of("out_of_order",
                                            Boolean.toString(event.outOfOrder()), "provider_object_id",
                                            event.providerObjectId(), "business_order_no",
                                            expected.businessOrderNo()));
        }
    }

    private static String uniqueHeader(Map<String, String> headers, String expected) {
        String result = null;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(expected)) {
                continue;
            }
            if (result != null) {
                throw new SecurityException("ambiguous Stripe webhook header: " + expected);
            }
            result = entry.getValue();
        }
        if (result == null) {
            throw new ProviderException("WEBHOOK_SIGNATURE_MISSING",
                    "Stripe-Signature is required", false, false);
        }
        if (result.isBlank() || result.length() > 4_096
                || result.chars().anyMatch(character -> character < 0x20
                        || character == 0x7f)) {
            throw new SecurityException("invalid Stripe webhook header: " + expected);
        }
        return result;
    }

    private static final class MissingDelegate implements ProviderAdapter {
        private final String code; MissingDelegate(String code) { this.code = code; }
        @Override public String provider() { return PROVIDER; }
        @Override public boolean configured() { return false; }
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) { throw missing(); }
        @Override public ProviderPayment queryPayment(ProviderRequestContext c, String id, String order) { throw missing(); }
        @Override public ProviderPayment capture(ProviderRequestContext c, String id, Money amount) { throw missing(); }
        @Override public ProviderPayment cancel(ProviderRequestContext c, String id, String reason) { throw missing(); }
        @Override public ProviderRefund refund(RefundCommand command) { throw missing(); }
        @Override public ProviderRefund queryRefund(ProviderRequestContext c, String id, String ref) { throw missing(); }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) { throw missing(); }
        private ProviderException missing() { return new ProviderException(code, "Stripe provider is not configured", false, false); }
    }

    private static ProviderPayment payment(ProviderRequestContext context, String fallback,
            StripeAdapter.OperationResult result, Money amount, Map<String, String> action) {
        ProviderOutcome outcome = outcome(result.state());
        Money authorized = outcome == ProviderOutcome.AUTHORIZED || outcome == ProviderOutcome.SUCCEEDED ? amount : null;
        Money captured = outcome == ProviderOutcome.SUCCEEDED ? amount : null;
        String id = result.providerReference().isBlank() ? fallback : result.providerReference();
        return new ProviderPayment(context.idempotencyKey(), id, outcome, authorized, captured,
                result.finalState(), action);
    }
    private static ProviderRefund refundResult(String fallback, StripeAdapter.OperationResult result, Money amount) {
        return new ProviderRefund(result.providerReference().isBlank() ? fallback : result.providerReference(),
                outcome(result.state()), result.state() == StripeAdapter.State.SUCCEEDED ? amount : null,
                result.finalState());
    }
    private static ProviderOutcome outcome(StripeAdapter.State state) {
        return switch (state) {
            case REQUIRES_ACTION -> ProviderOutcome.REQUIRES_ACTION;
            case REQUIRES_CAPTURE -> ProviderOutcome.AUTHORIZED;
            case SUCCEEDED -> ProviderOutcome.SUCCEEDED;
            case FAILED -> ProviderOutcome.FAILED;
            case CANCELED -> ProviderOutcome.CANCELED;
            case PROCESSING, UNKNOWN -> ProviderOutcome.UNKNOWN;
        };
    }
    private static ProviderException failure(String code) {
        return new ProviderException(code, "Stripe operation is unsupported", false, false);
    }
}
