package com.elmpay.gateway;

import com.elmpay.merchant.MerchantControlPlane;
import com.elmpay.payment.PaymentService;
import com.elmpay.payment.refund.RefundApplicationService;
import com.elmpay.webhook.ingress.WebhookIngressRuntime;
import java.util.Objects;
import java.util.Optional;

public record RuntimeComponents(PaymentService payments, ApiAuthenticator authenticator,
        RefundApplicationService refunds, PaymentIntentMetadataRepository metadata,
        WebhookIngressRuntime webhookIngress, PaymentTimelineRuntime timeline,
        Optional<MerchantControlPlane> merchantControl, boolean baseReady, String mode,
        PaymentAdminCommandRuntime adminCommands) {
    public RuntimeComponents(PaymentService payments, ApiAuthenticator authenticator,
            RefundApplicationService refunds, PaymentIntentMetadataRepository metadata,
            WebhookIngressRuntime webhookIngress, PaymentTimelineRuntime timeline, boolean ready,
            String mode) {
        this(payments, authenticator, refunds, metadata, webhookIngress, timeline,
                Optional.empty(), ready, mode,
                PaymentAdminCommandRuntime.disabled(java.time.Clock.systemUTC()));
    }

    public RuntimeComponents(PaymentService payments, ApiAuthenticator authenticator,
            RefundApplicationService refunds, PaymentIntentMetadataRepository metadata,
            boolean ready, String mode) {
        this(payments, authenticator, refunds, metadata, null,
                PaymentTimelineRuntime.unavailable(), Optional.empty(), ready, mode,
                PaymentAdminCommandRuntime.disabled(java.time.Clock.systemUTC()));
    }

    public RuntimeComponents(PaymentService payments, ApiAuthenticator authenticator,
            RefundApplicationService refunds, PaymentIntentMetadataRepository metadata,
            WebhookIngressRuntime webhookIngress, boolean ready, String mode) {
        this(payments, authenticator, refunds, metadata, webhookIngress,
                PaymentTimelineRuntime.unavailable(), Optional.empty(), ready, mode,
                PaymentAdminCommandRuntime.disabled(java.time.Clock.systemUTC()));
    }

    public RuntimeComponents(PaymentService payments, ApiAuthenticator authenticator,
            RefundApplicationService refunds, boolean ready, String mode) {
        this(payments, authenticator, refunds, null, null, PaymentTimelineRuntime.unavailable(),
                Optional.empty(), ready, mode,
                PaymentAdminCommandRuntime.disabled(java.time.Clock.systemUTC()));
    }

    /** Compatibility constructor for callers that only provide the payment runtime. */
    public RuntimeComponents(PaymentService payments, ApiAuthenticator authenticator,
            boolean ready, String mode) {
        this(payments, authenticator, null, null, null, PaymentTimelineRuntime.unavailable(),
                Optional.empty(), ready, mode,
                PaymentAdminCommandRuntime.disabled(java.time.Clock.systemUTC()));
    }

    public RuntimeComponents {
        Objects.requireNonNull(payments, "payments");
        Objects.requireNonNull(authenticator, "authenticator");
        Objects.requireNonNull(timeline, "timeline");
        Objects.requireNonNull(merchantControl, "merchantControl");
        Objects.requireNonNull(adminCommands, "adminCommands");
        Objects.requireNonNull(mode, "mode");
    }

    public boolean ready() {
        return baseReady && adminCommands.ready();
    }
}
