package com.elmpay.payment.refund;

import com.elmpay.payment.PaymentIntent;
import java.time.Instant;
import java.util.Objects;

/** Risk policy consumes only server-derived signals and a digest of device context. */
@FunctionalInterface
public interface RefundRiskPolicy {
    RefundRiskDecision decide(Context context);

    record Context(PaymentIntent paymentIntent, RefundRequestCommand command, Instant evaluatedAt) {
        public Context {
            Objects.requireNonNull(paymentIntent, "paymentIntent");
            Objects.requireNonNull(command, "command");
            Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        }
    }
}
