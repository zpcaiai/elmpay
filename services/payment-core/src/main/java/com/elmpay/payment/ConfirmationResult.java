package com.elmpay.payment;

import java.util.Map;
import java.util.Objects;

public record ConfirmationResult(PaymentIntent intent, PaymentAttempt attempt,
        Map<String, String> clientAction, boolean replayed) {
    public ConfirmationResult {
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(attempt, "attempt");
        Objects.requireNonNull(clientAction, "clientAction");
        clientAction = Map.copyOf(clientAction);
    }
}
