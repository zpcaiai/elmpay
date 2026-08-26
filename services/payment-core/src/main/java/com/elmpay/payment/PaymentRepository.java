package com.elmpay.payment;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PaymentRepository {
    PaymentIntent create(PaymentIntent intent);

    Optional<PaymentIntent> find(UUID tenantId, UUID intentId);

    Optional<PaymentIntent> findByExternalReference(UUID tenantId, UUID projectId,
            String externalReference);

    Optional<PaymentIntent> findByCreateKey(UUID tenantId, UUID projectId, String idempotencyKey);

    PaymentIntent update(PaymentIntent intent, long expectedVersion, String eventType,
            String correlationId);

    Optional<PaymentActionReceipt> findActionReceipt(UUID tenantId, UUID intentId,
            String idempotencyKey);

    PaymentIntent updateWithActionReceipt(PaymentIntent intent, long expectedVersion,
            PaymentActionReceipt receipt, String eventType, String correlationId);

    PaymentAttempt beginAttempt(AttemptDraft draft);

    PaymentIntent resolveAttempt(PaymentAttempt attempt, PaymentIntent intent,
            long expectedIntentVersion, String eventType, String correlationId);

    PaymentIntent resolveRecovery(PaymentAttempt originalAttempt, PaymentAttempt queryAttempt,
            PaymentIntent intent, long expectedIntentVersion, String eventType,
            String correlationId);

    List<PaymentAttempt> attempts(UUID tenantId, UUID intentId);
}
