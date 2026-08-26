package com.elmpay.connectors.wechatpay;

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
import java.util.function.Supplier;

/** ServiceLoader bridge. The configured factory resolves credentials through the deployment secret plane. */
public final class WechatProviderBridge implements ProviderAdapter {
    private static final String PROVIDER = "wechat";
    private static final String PROPERTY = "elmpay.wechat.adapterFactory";
    private static final String ENVIRONMENT = "ELMPAY_WECHAT_ADAPTER_FACTORY";
    private final ProviderAdapter delegate;

    @FunctionalInterface
    public interface OriginalAmountResolver {
        long originalAmountMinor(RefundCommand command);
    }

    @FunctionalInterface
    public interface WebhookExpectationResolver {
        WechatPayAdapter.ExpectedWebhook resolve(WebhookRequest request);
    }

    public record Runtime(WechatPayAdapter adapter, OriginalAmountResolver originalAmounts,
            WebhookExpectationResolver webhookExpectations) {
        public Runtime {
            Objects.requireNonNull(adapter, "adapter");
            Objects.requireNonNull(originalAmounts, "originalAmounts");
            Objects.requireNonNull(webhookExpectations, "webhookExpectations");
        }
    }

    public WechatProviderBridge() {
        this(load());
    }

    public WechatProviderBridge(ProviderAdapter delegate) {
        this.delegate = requireProvider(delegate);
    }

    public WechatProviderBridge(Runtime runtime) {
        this.delegate = new StrongDelegate(runtime);
    }

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
        String factoryName = System.getProperty(PROPERTY);
        if (factoryName == null || factoryName.isBlank()) {
            factoryName = System.getenv(ENVIRONMENT);
        }
        if (factoryName == null || factoryName.isBlank()) {
            return new MissingDelegate("PROVIDER_CONFIG_MISSING");
        }
        try {
            Object value = Class.forName(factoryName, true, Thread.currentThread().getContextClassLoader())
                    .getConstructor().newInstance();
            if (!(value instanceof Supplier<?> supplier)) {
                throw new IllegalStateException("configured WeChat adapter factory must implement Supplier");
            }
            Object adapter = supplier.get();
            if (adapter instanceof Runtime runtime) {
                return new StrongDelegate(runtime);
            }
            if (!(adapter instanceof ProviderAdapter providerAdapter)) {
                throw new IllegalStateException("configured WeChat adapter factory returned an invalid adapter");
            }
            return requireProvider(providerAdapter);
        } catch (ReflectiveOperationException | RuntimeException exception) {
            return new MissingDelegate("PROVIDER_CONFIG_INVALID");
        }
    }

    private static ProviderAdapter requireProvider(ProviderAdapter adapter) {
        Objects.requireNonNull(adapter, "adapter");
        if (!PROVIDER.equals(adapter.provider()) || adapter instanceof WechatProviderBridge) {
            throw new IllegalArgumentException("WeChat bridge requires a non-bridge WeChat adapter");
        }
        return adapter;
    }

    private static final class StrongDelegate implements ProviderAdapter {
        private final Runtime runtime;

        StrongDelegate(Runtime runtime) { this.runtime = Objects.requireNonNull(runtime, "runtime"); }
        @Override public String provider() { return PROVIDER; }

        @Override
        public ProviderPayment createPayment(CreatePaymentCommand command) {
            WechatPayAdapter.Channel channel = switch (command.method()) {
                case "wechat_jsapi" -> WechatPayAdapter.Channel.JSAPI;
                case "wechat_mini_program" -> WechatPayAdapter.Channel.MINI_PROGRAM;
                case "wechat_native" -> WechatPayAdapter.Channel.NATIVE;
                case "wechat_h5" -> WechatPayAdapter.Channel.H5;
                case "wechat_app" -> WechatPayAdapter.Channel.APP;
                default -> throw failure("PAYMENT_METHOD_UNSUPPORTED");
            };
            Map<String, String> parameters = command.providerParameters();
            WechatPayAdapter.PaymentRequest request = new WechatPayAdapter.PaymentRequest(
                    command.businessOrderNo(), command.amount().amountMinor(),
                    command.amount().currency().code(), parameters.getOrDefault("description",
                            command.businessOrderNo()), channel, parameters.get("openid"),
                    parameters.get("client_ip"), parameters.get("h5_type"),
                    command.context().idempotencyKey());
            WechatPayAdapter.OperationResult result = runtime.adapter().createPayment(request);
            Map<String, String> action = result.providerReference().isBlank() ? Map.of()
                    : runtime.adapter().buildClientAction(channel, result.providerReference()).parameters();
            return payment(command.context(), command.businessOrderNo(), result, command.amount(), action);
        }

        @Override
        public ProviderPayment queryPayment(ProviderRequestContext context, String providerPaymentId,
                String businessOrderNo) {
            WechatPayAdapter.OperationResult result = runtime.adapter().queryPayment(businessOrderNo,
                    context.idempotencyKey());
            return payment(context, providerPaymentId, result, null, Map.of());
        }

        @Override
        public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId, Money amount) {
            throw failure("CAPTURE_UNSUPPORTED");
        }

        @Override
        public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId, String reason) {
            WechatPayAdapter.OperationResult result = runtime.adapter().closePayment(providerPaymentId,
                    context.idempotencyKey());
            return payment(context, providerPaymentId, result, null, Map.of());
        }

        @Override
        public ProviderRefund refund(RefundCommand command) {
            long original = runtime.originalAmounts().originalAmountMinor(command);
            WechatPayAdapter.OperationResult result = runtime.adapter().refund(command.providerPaymentId(),
                    command.refundId().toString(), command.amount().amountMinor(), original,
                    command.amount().currency().code(), command.context().idempotencyKey());
            return refundResult(command.refundId().toString(), result, command.amount());
        }

        @Override
        public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
                String refundReference) {
            WechatPayAdapter.OperationResult result = runtime.adapter().queryRefund(refundReference,
                    context.idempotencyKey());
            return refundResult(providerRefundId, result, null);
        }

        @Override
        public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
            WechatPayAdapter.VerifiedWebhook event = runtime.adapter().verifyWebhook(request.headers(),
                    request.rawBody(), request.receivedAt(), runtime.webhookExpectations().resolve(request));
            return new VerifiedProviderEvent(request.tenantId(), request.merchantAccountId(), event.eventId(),
                    event.eventType(), event.transactionId(), event.outTradeNo(),
                    Money.of(event.amountMinor(), event.currency()), event.signatureSerial(), request.receivedAt(),
                    Map.of("transaction_id", event.transactionId(), "out_trade_no", event.outTradeNo(),
                            "amount_minor", Long.toString(event.amountMinor()), "currency", event.currency()));
        }
    }

    private static final class MissingDelegate implements ProviderAdapter {
        private final String code;
        MissingDelegate(String code) { this.code = code; }
        @Override public String provider() { return PROVIDER; }
        @Override public boolean configured() { return false; }
        @Override public ProviderPayment createPayment(CreatePaymentCommand command) { throw missing(); }
        @Override public ProviderPayment queryPayment(ProviderRequestContext context, String id, String order) { throw missing(); }
        @Override public ProviderPayment capture(ProviderRequestContext context, String id, Money amount) { throw missing(); }
        @Override public ProviderPayment cancel(ProviderRequestContext context, String id, String reason) { throw missing(); }
        @Override public ProviderRefund refund(RefundCommand command) { throw missing(); }
        @Override public ProviderRefund queryRefund(ProviderRequestContext context, String id, String ref) { throw missing(); }
        @Override public VerifiedProviderEvent verifyWebhook(WebhookRequest request) { throw missing(); }
        private ProviderException missing() { return new ProviderException(code, "WeChat provider is not configured", false, false); }
    }

    private static ProviderPayment payment(ProviderRequestContext context, String fallbackId,
            WechatPayAdapter.OperationResult result, Money amount, Map<String, String> action) {
        ProviderOutcome outcome = outcome(result.state());
        Money paid = outcome == ProviderOutcome.SUCCEEDED ? amount : null;
        String providerId = amount != null || result.providerReference().isBlank()
                ? fallbackId : result.providerReference();
        return new ProviderPayment(context.idempotencyKey(), providerId, outcome, paid, paid,
                result.finalState(), action);
    }

    private static ProviderRefund refundResult(String fallbackId, WechatPayAdapter.OperationResult result,
            Money amount) {
        return new ProviderRefund(result.providerReference().isBlank() ? fallbackId : result.providerReference(),
                outcome(result.state()), result.state() == WechatPayAdapter.State.SUCCEEDED ? amount : null,
                result.finalState());
    }

    private static ProviderOutcome outcome(WechatPayAdapter.State state) {
        return switch (state) {
            case PENDING -> ProviderOutcome.REQUIRES_ACTION;
            case SUCCEEDED -> ProviderOutcome.SUCCEEDED;
            case FAILED -> ProviderOutcome.FAILED;
            case CLOSED -> ProviderOutcome.CANCELED;
            case UNKNOWN -> ProviderOutcome.UNKNOWN;
        };
    }

    private static ProviderException failure(String code) {
        return new ProviderException(code, "WeChat operation is unsupported", false, false);
    }
}
