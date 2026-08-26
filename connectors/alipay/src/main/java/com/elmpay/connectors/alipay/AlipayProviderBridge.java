package com.elmpay.connectors.alipay;

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
import java.net.URI;
import java.util.Map;
import java.util.function.Supplier;

/** ServiceLoader bridge whose external factory supplies the certificate/KMS-configured adapter. */
public final class AlipayProviderBridge implements ProviderAdapter {
    private static final String PROVIDER = "alipay";
    private static final String PROPERTY = "elmpay.alipay.adapterFactory";
    private static final String ENVIRONMENT = "ELMPAY_ALIPAY_ADAPTER_FACTORY";
    private final ProviderAdapter delegate;

    @FunctionalInterface public interface ReturnUriResolver { URI resolve(String approvedRouteId); }
    @FunctionalInterface public interface NotifyExpectationResolver {
        AlipayAdapter.ExpectedNotify resolve(WebhookRequest request);
    }
    @FunctionalInterface public interface RefundPaymentResolver {
        String outTradeNo(String providerRefundId, String refundReference);
    }
    public record Runtime(AlipayAdapter adapter, ReturnUriResolver returnUris,
            NotifyExpectationResolver notifyExpectations, RefundPaymentResolver refundPayments) {
        public Runtime {
            Objects.requireNonNull(adapter, "adapter"); Objects.requireNonNull(returnUris, "returnUris");
            Objects.requireNonNull(notifyExpectations, "notifyExpectations");
            Objects.requireNonNull(refundPayments, "refundPayments");
        }
    }

    public AlipayProviderBridge() { this(load()); }
    public AlipayProviderBridge(ProviderAdapter delegate) { this.delegate = requireProvider(delegate); }
    public AlipayProviderBridge(Runtime runtime) { this.delegate = new StrongDelegate(runtime); }
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
                throw new IllegalStateException("configured Alipay factory must implement Supplier");
            }
            Object supplied = supplier.get();
            if (supplied instanceof Runtime runtime) return new StrongDelegate(runtime);
            if (supplied instanceof ProviderAdapter adapter) return requireProvider(adapter);
            throw new IllegalStateException("configured Alipay factory returned an invalid adapter");
        } catch (ReflectiveOperationException | RuntimeException exception) {
            return new MissingDelegate("PROVIDER_CONFIG_INVALID");
        }
    }

    private static ProviderAdapter requireProvider(ProviderAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        if (!PROVIDER.equals(adapter.provider()) || adapter instanceof AlipayProviderBridge) {
            throw new IllegalArgumentException("Alipay bridge requires a non-bridge Alipay adapter");
        }
        return adapter;
    }

    private static final class StrongDelegate implements ProviderAdapter {
        private final Runtime runtime;
        StrongDelegate(Runtime runtime) { this.runtime = Objects.requireNonNull(runtime, "runtime"); }
        @Override public String provider() { return PROVIDER; }
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) {
            AlipayAdapter.Channel channel = switch (command.method()) {
                case "alipay_web" -> AlipayAdapter.Channel.WEB;
                case "alipay_wap" -> AlipayAdapter.Channel.WAP;
                case "alipay_app" -> AlipayAdapter.Channel.APP;
                case "alipay_qr" -> AlipayAdapter.Channel.QR;
                case "alipay_mini_program" -> AlipayAdapter.Channel.MINI_PROGRAM;
                default -> throw failure("PAYMENT_METHOD_UNSUPPORTED");
            };
            Map<String, String> parameters = command.providerParameters();
            URI returnUri = command.approvedReturnRouteId() == null ? null
                    : runtime.returnUris().resolve(command.approvedReturnRouteId());
            AlipayAdapter.OperationResult result = runtime.adapter().createOrder(new AlipayAdapter.PaymentRequest(
                    command.businessOrderNo(), command.amount().amountMinor(), command.amount().currency().code(),
                    parameters.getOrDefault("subject", command.businessOrderNo()), channel,
                    parameters.get("store_id"), command.context().idempotencyKey()), returnUri);
            return payment(command.context(), command.businessOrderNo(), result, command.amount(),
                    result.responseBody().isBlank() ? Map.of() : Map.of("provider_action", result.responseBody()));
        }
        @Override public ProviderPayment queryPayment(ProviderRequestContext context, String providerPaymentId,
                String businessOrderNo) {
            return payment(context, providerPaymentId, runtime.adapter().query(businessOrderNo,
                    context.idempotencyKey()), null, Map.of());
        }
        @Override public ProviderPayment capture(ProviderRequestContext context, String id, Money amount) {
            throw failure("CAPTURE_UNSUPPORTED");
        }
        @Override public ProviderPayment cancel(ProviderRequestContext context, String id, String reason) {
            return payment(context, id, runtime.adapter().close(id, context.idempotencyKey()), null, Map.of());
        }
        @Override public ProviderRefund refund(RefundCommand command) {
            AlipayAdapter.OperationResult result = runtime.adapter().refund(command.providerPaymentId(),
                    command.refundId().toString(), command.amount().amountMinor(),
                    command.context().idempotencyKey());
            return refundResult(command.refundId().toString(), result, command.amount());
        }
        @Override public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
                String refundReference) {
            String order = runtime.refundPayments().outTradeNo(providerRefundId, refundReference);
            return refundResult(providerRefundId, runtime.adapter().queryRefund(order, refundReference,
                    context.idempotencyKey()), null);
        }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            AlipayAdapter.VerifiedNotify event = runtime.adapter().verifyNotify(request.rawBody(),
                    request.receivedAt(), runtime.notifyExpectations().resolve(request));
            return new VerifiedProviderEvent(request.tenantId(), request.merchantAccountId(), event.eventId(),
                    "alipay." + event.tradeStatus().toLowerCase(java.util.Locale.ROOT), event.tradeNo(),
                    event.outTradeNo(), Money.of(event.amountMinor(), event.currency()), event.certificateSerial(),
                    request.receivedAt(), Map.of("trade_status", event.tradeStatus(), "trade_no", event.tradeNo(),
                            "amount_minor", Long.toString(event.amountMinor()), "currency", event.currency()));
        }
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
        private ProviderException missing() { return new ProviderException(code, "Alipay provider is not configured", false, false); }
    }

    private static ProviderPayment payment(ProviderRequestContext context, String fallback,
            AlipayAdapter.OperationResult result, Money amount, Map<String, String> action) {
        ProviderOutcome outcome = outcome(result.state());
        Money paid = outcome == ProviderOutcome.SUCCEEDED ? amount : null;
        String id = amount != null || result.providerReference().isBlank() ? fallback : result.providerReference();
        return new ProviderPayment(context.idempotencyKey(), id, outcome, paid, paid,
                result.finalState(), action);
    }
    private static ProviderRefund refundResult(String fallback, AlipayAdapter.OperationResult result, Money amount) {
        return new ProviderRefund(result.providerReference().isBlank() ? fallback : result.providerReference(),
                outcome(result.state()), result.state() == AlipayAdapter.State.SUCCEEDED ? amount : null,
                result.finalState());
    }
    private static ProviderOutcome outcome(AlipayAdapter.State state) {
        return switch (state) {
            case PENDING -> ProviderOutcome.REQUIRES_ACTION; case SUCCEEDED -> ProviderOutcome.SUCCEEDED;
            case FAILED -> ProviderOutcome.FAILED; case CLOSED -> ProviderOutcome.CANCELED;
            case UNKNOWN -> ProviderOutcome.UNKNOWN;
        };
    }
    private static ProviderException failure(String code) {
        return new ProviderException(code, "Alipay operation is unsupported", false, false);
    }
}
