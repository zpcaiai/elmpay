package com.elmpay.connectors.paypal;

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
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/** ServiceLoader bridge from the common provider port to the Orders v2 adapter. */
public final class PayPalProviderBridge implements ProviderAdapter {
    private static final String PROVIDER = "paypal";
    private static final String PROPERTY = "elmpay.paypal.adapterFactory";
    private static final String ENVIRONMENT = "ELMPAY_PAYPAL_ADAPTER_FACTORY";
    private final ProviderAdapter delegate;

    @FunctionalInterface
    public interface WebhookExpectationResolver {
        PayPalAdapter.ExpectedWebhook resolve(WebhookRequest request);
    }

    public record Runtime(PayPalAdapter adapter, WebhookExpectationResolver webhookExpectations) {
        public Runtime {
            Objects.requireNonNull(adapter, "adapter");
            Objects.requireNonNull(webhookExpectations, "webhookExpectations");
        }
    }

    public PayPalProviderBridge() { this(load()); }
    public PayPalProviderBridge(ProviderAdapter delegate) { this.delegate = requireProvider(delegate); }
    public PayPalProviderBridge(Runtime runtime) { this.delegate = new StrongDelegate(runtime); }
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
                throw new IllegalStateException("configured PayPal factory must implement Supplier");
            }
            Object supplied = supplier.get();
            if (supplied instanceof Runtime runtime) return new StrongDelegate(runtime);
            if (supplied instanceof ProviderAdapter adapter) return requireProvider(adapter);
            throw new IllegalStateException("configured PayPal factory returned an invalid adapter");
        } catch (ReflectiveOperationException | RuntimeException exception) {
            return new MissingDelegate("PROVIDER_CONFIG_INVALID");
        }
    }

    private static ProviderAdapter requireProvider(ProviderAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        if (!PROVIDER.equals(adapter.provider()) || adapter instanceof PayPalProviderBridge) {
            throw new IllegalArgumentException("PayPal bridge requires a non-bridge PayPal adapter");
        }
        return adapter;
    }

    private static final class StrongDelegate implements ProviderAdapter {
        private final Runtime runtime;
        StrongDelegate(Runtime runtime) { this.runtime = Objects.requireNonNull(runtime, "runtime"); }
        @Override public String provider() { return PROVIDER; }

        @Override
        public ProviderPayment createPayment(CreatePaymentCommand command) {
            if (!"paypal".equals(command.method())) throw failure("PAYMENT_METHOD_UNSUPPORTED");
            Map<String, String> parameters = command.providerParameters();
            String returnRoute = command.approvedReturnRouteId();
            String cancelRoute = parameters.get("cancel_route_id");
            if (returnRoute == null || cancelRoute == null) throw failure("APPROVED_ROUTE_REQUIRED");
            boolean authorizeOnly = "AUTHORIZE".equalsIgnoreCase(parameters.getOrDefault("intent", "CAPTURE"));
            PayPalAdapter.OperationResult result = runtime.adapter().createOrder(new PayPalAdapter.OrderRequest(
                    command.businessOrderNo(), command.amount().amountMinor(), command.amount().currency().code(),
                    command.amount().currency().fractionDigits(), authorizeOnly, returnRoute, cancelRoute,
                    command.context().idempotencyKey()));
            Map<String, String> action = result.responseBody().isBlank() ? Map.of()
                    : Map.of("provider_action", result.responseBody());
            return payment(command.context(), command.businessOrderNo(), result, command.amount(), action);
        }

        @Override
        public ProviderPayment queryPayment(ProviderRequestContext context, String id, String businessOrderNo) {
            return payment(context, id, runtime.adapter().queryOrder(id), null, Map.of());
        }

        @Override
        public ProviderPayment capture(ProviderRequestContext context, String id, Money amount) {
            return payment(context, id, runtime.adapter().capture(id, context.idempotencyKey()), amount, Map.of());
        }

        @Override
        public ProviderPayment cancel(ProviderRequestContext context, String id, String reason) {
            return payment(context, id, runtime.adapter().voidAuthorization(id, context.idempotencyKey()), null,
                    Map.of());
        }

        @Override
        public ProviderRefund refund(RefundCommand command) {
            PayPalAdapter.OperationResult result = runtime.adapter().refund(command.providerPaymentId(),
                    command.amount().amountMinor(), command.amount().currency().code(),
                    command.amount().currency().fractionDigits(), command.refundId().toString(),
                    command.context().idempotencyKey());
            return refundResult(command.refundId().toString(), result, command.amount());
        }

        @Override
        public ProviderRefund queryRefund(ProviderRequestContext context, String id, String reference) {
            return refundResult(id, runtime.adapter().queryRefund(id), null);
        }

        @Override
        public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            PayPalAdapter.ExpectedWebhook expected = runtime.webhookExpectations().resolve(request);
            PayPalAdapter.VerifiedWebhook event = runtime.adapter().verifyWebhook(request.headers(),
                    request.rawBody(), expected);
            return new VerifiedProviderEvent(request.tenantId(), request.merchantAccountId(), event.eventId(),
                    event.eventType(), event.providerObjectId(), "",
                    Money.of(event.amountMinor(), event.currency()), header(request.headers(),
                            "PAYPAL-TRANSMISSION-ID"), request.receivedAt(),
                    Map.of("provider_object_id", event.providerObjectId(), "amount_minor",
                            Long.toString(event.amountMinor()), "currency", event.currency()));
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
            return new ProviderException(code, "PayPal provider is not configured", false, false);
        }
    }

    private static ProviderPayment payment(ProviderRequestContext context, String fallback,
            PayPalAdapter.OperationResult result, Money amount, Map<String, String> action) {
        ProviderOutcome outcome = outcome(result.state());
        Money authorized = outcome == ProviderOutcome.AUTHORIZED || outcome == ProviderOutcome.SUCCEEDED
                ? amount : null;
        Money captured = outcome == ProviderOutcome.SUCCEEDED ? amount : null;
        String id = result.providerReference().isBlank() ? fallback : result.providerReference();
        return new ProviderPayment(context.idempotencyKey(), id, outcome, authorized, captured,
                result.finalState(), action);
    }

    private static ProviderRefund refundResult(String fallback, PayPalAdapter.OperationResult result, Money amount) {
        return new ProviderRefund(result.providerReference().isBlank() ? fallback : result.providerReference(),
                outcome(result.state()), result.state() == PayPalAdapter.State.SUCCEEDED ? amount : null,
                result.finalState());
    }

    private static ProviderOutcome outcome(PayPalAdapter.State state) {
        return switch (state) {
            case CREATED, APPROVAL_REQUIRED -> ProviderOutcome.REQUIRES_ACTION;
            case AUTHORIZED -> ProviderOutcome.AUTHORIZED;
            case SUCCEEDED -> ProviderOutcome.SUCCEEDED;
            case FAILED -> ProviderOutcome.FAILED;
            case VOIDED -> ProviderOutcome.CANCELED;
            case PROCESSING, UNKNOWN -> ProviderOutcome.UNKNOWN;
        };
    }

    private static String header(Map<String, String> headers, String name) {
        return headers.entrySet().stream().filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue).filter(Objects::nonNull).findFirst()
                .orElseThrow(() -> failure("WEBHOOK_SIGNATURE_MISSING"));
    }

    private static ProviderException failure(String code) {
        return new ProviderException(code, "PayPal operation is unsupported or missing approved routing",
                false, false);
    }
}
