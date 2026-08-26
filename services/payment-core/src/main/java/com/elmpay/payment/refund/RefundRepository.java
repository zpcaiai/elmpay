package com.elmpay.payment.refund;

import java.util.Optional;
import java.util.UUID;

/** Durable transaction boundary for refund reservation, state, action receipts and outbox. */
public interface RefundRepository {
    record WriteResult(RefundRecord refund, boolean replay) {
    }

    Optional<RefundRecord> find(UUID tenantId, UUID refundId);

    Optional<RefundRecord> findByRequestKey(UUID tenantId, String idempotencyKey);

    Optional<RefundActionReceipt> findActionReceipt(UUID tenantId, UUID refundId,
            String idempotencyKey);

    WriteResult createAndReserve(RefundRecord proposed, long capturedAmountMinor,
            long alreadyRefundedAmountMinor, String eventType);

    WriteResult transitionWithReceipt(RefundRecord expected, RefundRecord proposed,
            RefundActionReceipt receipt, String eventType);

    WriteResult claimAction(RefundRecord expected, RefundActionReceipt receipt,
            String eventType);

    RefundRecord recordProviderOutcome(RefundRecord expected, RefundRecord proposed,
            String eventType);

    long remainingRefundable(UUID tenantId, UUID paymentIntentId, long capturedAmountMinor,
            long alreadyRefundedAmountMinor);
}
