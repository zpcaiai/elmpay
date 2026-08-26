package com.elmpay.payment.refund;

import com.elmpay.payment.PaymentCoreException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Thread-safe reference repository used by local runtime and concurrency tests. */
public final class InMemoryRefundRepository implements RefundRepository {
    private final Map<UUID, RefundRecord> refunds = new HashMap<>();
    private final Map<RequestKey, UUID> requestKeys = new HashMap<>();
    private final Map<ActionKey, RefundActionReceipt> actionReceipts = new HashMap<>();
    private final List<RefundOutboxEvent> outbox = new ArrayList<>();

    @Override
    public synchronized Optional<RefundRecord> find(UUID tenantId, UUID refundId) {
        RefundRecord refund = refunds.get(refundId);
        return refund != null && refund.tenantId().equals(tenantId)
                ? Optional.of(refund) : Optional.empty();
    }

    @Override
    public synchronized Optional<RefundRecord> findByRequestKey(UUID tenantId,
            String idempotencyKey) {
        UUID id = requestKeys.get(new RequestKey(tenantId, idempotencyKey));
        return id == null ? Optional.empty() : find(tenantId, id);
    }

    @Override
    public synchronized Optional<RefundActionReceipt> findActionReceipt(UUID tenantId,
            UUID refundId, String idempotencyKey) {
        RefundActionReceipt receipt = actionReceipts.get(new ActionKey(tenantId, idempotencyKey));
        return receipt != null && receipt.refundId().equals(refundId)
                ? Optional.of(receipt) : Optional.empty();
    }

    @Override
    public synchronized WriteResult createAndReserve(RefundRecord proposed,
            long capturedAmountMinor, long alreadyRefundedAmountMinor, String eventType) {
        validatePaymentAmounts(capturedAmountMinor, alreadyRefundedAmountMinor);
        RequestKey key = new RequestKey(proposed.tenantId(), proposed.requestIdempotencyKey());
        UUID existingId = requestKeys.get(key);
        if (existingId != null) {
            RefundRecord existing = refunds.get(existingId);
            requireSameRequest(existing, proposed.requestDigest());
            return new WriteResult(existing, true);
        }
        if (actionReceipts.containsKey(new ActionKey(proposed.tenantId(),
                proposed.requestIdempotencyKey()))) {
            throw conflict("refund request key already belongs to an action");
        }
        if (refunds.containsKey(proposed.id())) {
            throw conflict("refund identifier already exists");
        }
        if (proposed.status().holdsReservation()) {
            long remaining = remainingRefundable(proposed.tenantId(), proposed.paymentIntentId(),
                    capturedAmountMinor, alreadyRefundedAmountMinor);
            if (proposed.amount().amountMinor() > remaining) {
                throw new PaymentCoreException("REFUND_AMOUNT_EXCEEDS_REFUNDABLE",
                        "refund exceeds the atomically reserved refundable amount");
            }
        }
        refunds.put(proposed.id(), proposed);
        requestKeys.put(key, proposed.id());
        appendEvent(proposed, eventType, null);
        return new WriteResult(proposed, false);
    }

    @Override
    public synchronized WriteResult transitionWithReceipt(RefundRecord expected,
            RefundRecord proposed, RefundActionReceipt receipt, String eventType) {
        RefundActionReceipt replay = actionReceipts.get(
                new ActionKey(receipt.tenantId(), receipt.idempotencyKey()));
        if (replay != null) {
            requireSameReceipt(replay, receipt);
            return new WriteResult(require(replay.tenantId(), replay.refundId()), true);
        }
        requireActionKeyUnusedByRequest(receipt);
        RefundRecord current = requireExpected(expected);
        requireTransition(current, proposed);
        requireReceipt(receipt, proposed);
        refunds.put(proposed.id(), proposed);
        actionReceipts.put(new ActionKey(receipt.tenantId(), receipt.idempotencyKey()), receipt);
        appendEvent(proposed, eventType, receipt);
        return new WriteResult(proposed, false);
    }

    @Override
    public synchronized WriteResult claimAction(RefundRecord expected,
            RefundActionReceipt receipt, String eventType) {
        RefundActionReceipt replay = actionReceipts.get(
                new ActionKey(receipt.tenantId(), receipt.idempotencyKey()));
        if (replay != null) {
            requireSameReceipt(replay, receipt);
            return new WriteResult(require(replay.tenantId(), replay.refundId()), true);
        }
        requireActionKeyUnusedByRequest(receipt);
        RefundRecord current = requireExpected(expected);
        if (receipt.resultVersion() != current.version()
                || !receipt.tenantId().equals(current.tenantId())
                || !receipt.refundId().equals(current.id())) {
            throw new PaymentCoreException("REFUND_ACTION_RECEIPT_INVALID",
                    "refund action receipt does not match the current aggregate");
        }
        actionReceipts.put(new ActionKey(receipt.tenantId(), receipt.idempotencyKey()), receipt);
        appendEvent(current, eventType, receipt);
        return new WriteResult(current, false);
    }

    @Override
    public synchronized RefundRecord recordProviderOutcome(RefundRecord expected,
            RefundRecord proposed, String eventType) {
        RefundRecord current = requireExpected(expected);
        requireTransition(current, proposed);
        refunds.put(proposed.id(), proposed);
        appendEvent(proposed, eventType, null);
        return proposed;
    }

    @Override
    public synchronized long remainingRefundable(UUID tenantId, UUID paymentIntentId,
            long capturedAmountMinor, long alreadyRefundedAmountMinor) {
        validatePaymentAmounts(capturedAmountMinor, alreadyRefundedAmountMinor);
        long pending = 0;
        long succeeded = 0;
        for (RefundRecord refund : refunds.values()) {
            if (!refund.tenantId().equals(tenantId)
                    || !refund.paymentIntentId().equals(paymentIntentId)) {
                continue;
            }
            if (refund.status() == RefundStatus.SUCCEEDED) {
                succeeded = Math.addExact(succeeded, refund.amount().amountMinor());
            } else if (refund.status() == RefundStatus.APPROVAL_PENDING
                    || refund.status() == RefundStatus.PROCESSING
                    || refund.status() == RefundStatus.UNKNOWN) {
                pending = Math.addExact(pending, refund.amount().amountMinor());
            }
        }
        long committed = Math.max(alreadyRefundedAmountMinor, succeeded);
        long used = Math.addExact(committed, pending);
        return Math.max(0, capturedAmountMinor - used);
    }

    public synchronized List<RefundOutboxEvent> outboxEvents() {
        return List.copyOf(outbox);
    }

    private RefundRecord requireExpected(RefundRecord expected) {
        RefundRecord current = require(expected.tenantId(), expected.id());
        if (current.version() != expected.version()
                || current.status() != expected.status()
                || !current.requestDigest().equals(expected.requestDigest())) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "refund changed during the operation");
        }
        return current;
    }

    private RefundRecord require(UUID tenantId, UUID refundId) {
        return find(tenantId, refundId).orElseThrow(() -> new PaymentCoreException(
                "RESOURCE_NOT_FOUND", "refund does not exist in this tenant"));
    }

    private void requireActionKeyUnusedByRequest(RefundActionReceipt receipt) {
        if (requestKeys.containsKey(new RequestKey(receipt.tenantId(), receipt.idempotencyKey()))) {
            throw conflict("refund action key already belongs to a create request");
        }
    }

    private static void requireSameRequest(RefundRecord existing, String expectedDigest) {
        if (!existing.sameRequestDigest(expectedDigest)) {
            throw conflict("refund request key was reused with a different canonical payload");
        }
    }

    private static void requireSameReceipt(RefundActionReceipt existing,
            RefundActionReceipt proposed) {
        if (!existing.refundId().equals(proposed.refundId())
                || !existing.matches(proposed.operation(), proposed.requestDigest())) {
            throw conflict("refund action key was reused with a different operation or payload");
        }
    }

    private static void requireReceipt(RefundActionReceipt receipt, RefundRecord proposed) {
        if (!receipt.tenantId().equals(proposed.tenantId())
                || !receipt.refundId().equals(proposed.id())
                || receipt.resultVersion() != proposed.version()) {
            throw new PaymentCoreException("REFUND_ACTION_RECEIPT_INVALID",
                    "refund action receipt does not match the resulting aggregate");
        }
    }

    private static void requireTransition(RefundRecord current, RefundRecord proposed) {
        if (!current.id().equals(proposed.id())
                || !current.tenantId().equals(proposed.tenantId())
                || !current.requestDigest().equals(proposed.requestDigest())
                || proposed.version() != current.version() + 1) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "invalid or stale refund transition");
        }
    }

    private void appendEvent(RefundRecord refund, String eventType,
            RefundActionReceipt receipt) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("refund_id", refund.id().toString());
        payload.put("payment_intent_id", refund.paymentIntentId().toString());
        payload.put("amount_minor", refund.amount().amountMinor());
        payload.put("currency", refund.amount().currency().code());
        payload.put("state", refund.status().name().toLowerCase(java.util.Locale.ROOT));
        payload.put("reason", refund.reason().wireValue());
        payload.put("requester_id", refund.requesterId());
        payload.put("risk_decision", refund.riskDecision().name());
        if (receipt != null) {
            payload.put("actor_id", receipt.actorId());
            payload.put("action_reason", receipt.reason());
            payload.put("ticket_id", receipt.ticketId());
        }
        outbox.add(new RefundOutboxEvent(UUID.randomUUID(), refund.tenantId(), refund.projectId(),
                refund.id(), eventType, refund.correlationId(), payload, refund.updatedAt()));
    }

    private static void validatePaymentAmounts(long captured, long refunded) {
        if (captured < 0 || refunded < 0 || refunded > captured) {
            throw new IllegalArgumentException("invalid captured/refunded payment amounts");
        }
    }

    private static PaymentCoreException conflict(String message) {
        return new PaymentCoreException("IDEMPOTENCY_KEY_REUSE", message);
    }

    private record RequestKey(UUID tenantId, String key) {
    }

    private record ActionKey(UUID tenantId, String key) {
    }
}
