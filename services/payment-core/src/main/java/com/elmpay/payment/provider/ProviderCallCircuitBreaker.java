package com.elmpay.payment.provider;

import java.util.UUID;

/** Central, account-scoped guard for every provider runtime invocation. */
public interface ProviderCallCircuitBreaker {
    enum Operation {
        CREATE_PAYMENT,
        QUERY_PAYMENT,
        CAPTURE,
        CANCEL,
        REFUND,
        QUERY_REFUND,
        VERIFY_WEBHOOK
    }

    @FunctionalInterface
    interface ProviderCall<T> {
        T invoke();
    }

    /**
     * Executes and classifies the supplied call. There is deliberately no caller-provided
     * success flag: the implementation derives the observation from the return value or the
     * captured exception.
     */
    <T> T execute(UUID tenantId, UUID providerAccountId, String provider,
            Operation operation, ProviderCall<T> call);
}
