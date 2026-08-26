package com.elmpay.gateway;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import com.elmpay.security.CanonicalPayload;
import java.util.Map;

/** Deterministic local adapter for tests and demos; guarded by an explicit runtime flag. */
public final class LocalSandboxProviderAdapter implements ProviderAdapter {
    @Override
    public String provider() {
        return "stripe";
    }

    @Override
    public ProviderPayment createPayment(CreatePaymentCommand command) {
        String transaction = "local_" + CanonicalPayload.sha256Hex(Map.of(
                "intent", command.paymentIntentId().toString(),
                "key", command.context().idempotencyKey())).substring(0, 24);
        String simulation = command.providerParameters().getOrDefault("simulation", "succeeded");
        return switch (simulation) {
            case "authorized" -> new ProviderPayment(transaction, transaction,
                    ProviderOutcome.AUTHORIZED, command.amount(), Money.of(0,
                            command.amount().currency().code()), true, Map.of());
            case "requires_action" -> new ProviderPayment(transaction, transaction,
                    ProviderOutcome.REQUIRES_ACTION, null, null, false,
                    Map.of("action", "local_challenge"));
            case "declined" -> new ProviderPayment(transaction, transaction,
                    ProviderOutcome.DECLINED, null, null, true,
                    Map.of("provider_code", "local_declined"));
            case "unknown" -> new ProviderPayment(transaction, transaction,
                    ProviderOutcome.UNKNOWN, null, null, false,
                    Map.of("provider_code", "local_unknown"));
            case "succeeded" -> new ProviderPayment(transaction, transaction,
                    ProviderOutcome.SUCCEEDED, command.amount(), command.amount(), true, Map.of());
            default -> throw new IllegalArgumentException("unsupported local simulation outcome");
        };
    }

    @Override
    public ProviderPayment queryPayment(ProviderRequestContext context, String providerPaymentId,
            String businessOrderNo) {
        return new ProviderPayment("query-" + providerPaymentId, providerPaymentId,
                ProviderOutcome.UNKNOWN, null, null, false,
                Map.of("provider_code", "local_query_unknown"));
    }

    @Override
    public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId,
            Money amount) {
        return new ProviderPayment("capture-" + providerPaymentId, providerPaymentId,
                ProviderOutcome.SUCCEEDED, amount, amount, true, Map.of());
    }

    @Override
    public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId,
            String reason) {
        return new ProviderPayment("cancel-" + providerPaymentId, providerPaymentId,
                ProviderOutcome.CANCELED, null, null, true, Map.of());
    }

    @Override
    public ProviderRefund refund(RefundCommand command) {
        return new ProviderRefund("local-refund-" + command.refundId(),
                ProviderOutcome.SUCCEEDED, command.amount(), true);
    }

    @Override
    public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
            String refundReference) {
        return new ProviderRefund(providerRefundId, ProviderOutcome.UNKNOWN, null, false);
    }

    @Override
    public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
        throw new UnsupportedOperationException("local sandbox does not accept provider webhooks");
    }
}
