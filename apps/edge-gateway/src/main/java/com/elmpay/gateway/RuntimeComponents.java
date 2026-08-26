package com.elmpay.gateway;

import com.elmpay.payment.PaymentService;
import com.elmpay.payment.refund.RefundApplicationService;
import java.util.Objects;

public record RuntimeComponents(PaymentService payments, ApiKeyAuthenticator authenticator,
        RefundApplicationService refunds, PaymentIntentMetadataRepository metadata, boolean ready,
        String mode) {
    public RuntimeComponents(PaymentService payments, ApiKeyAuthenticator authenticator,
            RefundApplicationService refunds, boolean ready, String mode) {
        this(payments, authenticator, refunds, null, ready, mode);
    }

    /** Compatibility constructor for callers that only provide the payment runtime. */
    public RuntimeComponents(PaymentService payments, ApiKeyAuthenticator authenticator,
            boolean ready, String mode) {
        this(payments, authenticator, null, null, ready, mode);
    }

    public RuntimeComponents {
        Objects.requireNonNull(payments, "payments");
        Objects.requireNonNull(authenticator, "authenticator");
        Objects.requireNonNull(mode, "mode");
    }
}
