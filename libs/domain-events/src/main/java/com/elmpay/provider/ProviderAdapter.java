package com.elmpay.provider;

import com.elmpay.money.Money;

/** Provider port. Implementations may call official SDKs but never own payment state. */
public interface ProviderAdapter {
    String provider();

    /** False when a ServiceLoader-visible adapter is present but its secret-backed runtime is absent. */
    default boolean configured() {
        return true;
    }

    ProviderPayment createPayment(CreatePaymentCommand command);

    ProviderPayment queryPayment(ProviderRequestContext context, String providerPaymentId,
            String businessOrderNo);

    ProviderPayment capture(ProviderRequestContext context, String providerPaymentId, Money amount);

    ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId, String reason);

    ProviderRefund refund(RefundCommand command);

    ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
            String refundReference);

    VerifiedProviderEvent verifyWebhook(WebhookRequest request);
}
