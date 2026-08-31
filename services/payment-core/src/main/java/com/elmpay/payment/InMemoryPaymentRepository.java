package com.elmpay.payment;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Thread-safe reference repository used for local runtime and deterministic concurrency tests. */
public final class InMemoryPaymentRepository implements PaymentRepository {
    private final Map<UUID, PaymentIntent> intents = new HashMap<>();
    private final Map<UUID, List<PaymentAttempt>> attempts = new HashMap<>();
    private final Map<ReceiptKey, PaymentActionReceipt> actionReceipts = new HashMap<>();

    @Override
    public synchronized PaymentIntent create(PaymentIntent intent) {
        findByExternalReference(intent.tenantId(), intent.projectId(), intent.externalReference())
                .ifPresent(existing -> {
                    throw new PaymentCoreException("EXTERNAL_REFERENCE_EXISTS",
                            "project order reference already has a payment intent");
                });
        findByCreateKey(intent.tenantId(), intent.projectId(), intent.createIdempotencyKey())
                .ifPresent(existing -> {
                    throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                            "idempotency key belongs to a different request");
                });
        if (intents.putIfAbsent(intent.id(), intent) != null) {
            throw new PaymentCoreException("PAYMENT_INTENT_EXISTS", "payment intent already exists");
        }
        return intent;
    }

    @Override
    public synchronized Optional<PaymentIntent> find(UUID tenantId, UUID intentId) {
        PaymentIntent intent = intents.get(intentId);
        return intent != null && intent.tenantId().equals(tenantId)
                ? Optional.of(intent) : Optional.empty();
    }

    @Override
    public synchronized Optional<PaymentIntent> findByExternalReference(UUID tenantId,
            UUID projectId, String externalReference) {
        return intents.values().stream()
                .filter(intent -> intent.tenantId().equals(tenantId)
                        && intent.projectId().equals(projectId)
                        && intent.externalReference().equals(externalReference))
                .findFirst();
    }

    @Override
    public synchronized Optional<PaymentIntent> findByCreateKey(UUID tenantId, UUID projectId,
            String idempotencyKey) {
        return intents.values().stream()
                .filter(intent -> intent.tenantId().equals(tenantId)
                        && intent.projectId().equals(projectId)
                        && intent.createIdempotencyKey().equals(idempotencyKey))
                .findFirst();
    }

    @Override
    public synchronized PaymentIntent update(PaymentIntent intent, long expectedVersion,
            String eventType, String correlationId) {
        PaymentIntent stored = requireIntent(intent.tenantId(), intent.id());
        if (stored.version() != expectedVersion || intent.version() != expectedVersion + 1) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "payment intent changed during the operation");
        }
        intents.put(intent.id(), intent);
        return intent;
    }

    @Override
    public synchronized Optional<PaymentActionReceipt> findActionReceipt(UUID tenantId,
            UUID intentId, String idempotencyKey) {
        requireIntent(tenantId, intentId);
        return Optional.ofNullable(actionReceipts.get(
                new ReceiptKey(tenantId, intentId, idempotencyKey)));
    }

    @Override
    public synchronized PaymentIntent updateWithActionReceipt(PaymentIntent intent,
            long expectedVersion, PaymentActionReceipt receipt, String eventType,
            String correlationId) {
        requireReceiptMatchesIntent(intent, receipt);
        ReceiptKey key = new ReceiptKey(receipt.tenantId(), receipt.intentId(),
                receipt.idempotencyKey());
        PaymentActionReceipt existing = actionReceipts.get(key);
        if (existing != null) {
            requireSameReceipt(existing, receipt);
            return requireIntent(intent.tenantId(), intent.id());
        }
        List<PaymentAttempt> currentAttempts = attempts.getOrDefault(intent.id(), List.of());
        if (currentAttempts.stream().anyMatch(attempt ->
                attempt.idempotencyKey().equals(receipt.idempotencyKey()))) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "action key already belongs to a provider operation");
        }
        if (currentAttempts.stream().anyMatch(attempt ->
                attempt.operation() != AttemptOperation.QUERY && !attempt.state().finalState())) {
            throw new PaymentCoreException("ATTEMPT_IN_PROGRESS",
                    "an unresolved provider call blocks direct cancellation");
        }
        PaymentIntent updated = update(intent, expectedVersion, eventType, correlationId);
        actionReceipts.put(key, receipt);
        return updated;
    }

    @Override
    public synchronized PaymentAttempt beginAttempt(AttemptDraft draft) {
        PaymentIntent intent = requireIntent(draft.tenantId(), draft.intentId());
        if (intent.version() != draft.expectedIntentVersion()) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "payment intent changed before provider dispatch");
        }
        List<PaymentAttempt> current = attempts.computeIfAbsent(draft.intentId(), key -> new ArrayList<>());
        if (actionReceipts.containsKey(new ReceiptKey(draft.tenantId(), draft.intentId(),
                draft.idempotencyKey()))) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "attempt key already belongs to a non-provider payment action");
        }
        if (current.stream().anyMatch(attempt -> attempt.idempotencyKey().equals(draft.idempotencyKey()))) {
            throw new PaymentCoreException("IDEMPOTENCY_REPLAY", "attempt key already exists");
        }
        boolean unresolvedMoneyMovement = current.stream().anyMatch(attempt ->
                attempt.operation() != AttemptOperation.QUERY && !attempt.state().finalState());
        boolean queryInProgress = current.stream().anyMatch(attempt ->
                attempt.operation() == AttemptOperation.QUERY
                        && (attempt.state() == AttemptState.INITIATED
                            || attempt.state() == AttemptState.PENDING)
                        && attempt.leaseExpiresAt().isAfter(draft.startedAt()));
        if ((draft.operation() == AttemptOperation.QUERY && queryInProgress)
                || (draft.operation() != AttemptOperation.QUERY && unresolvedMoneyMovement)) {
            throw new PaymentCoreException("ATTEMPT_IN_PROGRESS",
                    "an unresolved provider call blocks a new money movement");
        }
        PaymentAttempt attempt = PaymentAttempt.begin(draft, current.size() + 1);
        current.add(attempt);
        return attempt;
    }

    @Override
    public synchronized Optional<PaymentAttempt> claimRecoverableAttempt(UUID tenantId,
            UUID intentId, String leaseOwner, Instant now, Instant leaseExpiresAt) {
        requireIntent(tenantId, intentId);
        validateLease(leaseOwner, now, leaseExpiresAt);
        List<PaymentAttempt> current = attempts.getOrDefault(intentId, List.of());
        for (int index = current.size() - 1; index >= 0; index--) {
            PaymentAttempt candidate = current.get(index);
            if (candidate.tenantId().equals(tenantId)
                    && candidate.operation() != AttemptOperation.QUERY
                    && !candidate.state().finalState()
                    && !candidate.leaseExpiresAt().isAfter(now)) {
                PaymentAttempt claimed = candidate.withLease(leaseOwner,
                        Math.addExact(candidate.fencingToken(), 1), leaseExpiresAt);
                current.set(index, claimed);
                return Optional.of(claimed);
            }
        }
        return Optional.empty();
    }

    @Override
    public synchronized void releaseAttemptLease(PaymentAttempt attempt, Instant releasedAt) {
        java.util.Objects.requireNonNull(attempt, "attempt");
        java.util.Objects.requireNonNull(releasedAt, "releasedAt");
        requireIntent(attempt.tenantId(), attempt.intentId());
        List<PaymentAttempt> current = attempts.getOrDefault(attempt.intentId(), List.of());
        int index = attemptIndex(current, attempt.id());
        if (index < 0 || current.get(index).state().finalState()
                || !sameLease(current.get(index), attempt)) {
            throw new PaymentCoreException("ATTEMPT_LEASE_LOST",
                    "attempt recovery lease is no longer owned by this worker");
        }
        PaymentAttempt stored = current.get(index);
        current.set(index, stored.withLease(stored.leaseOwner(), stored.fencingToken(),
                releasedAt.isBefore(stored.startedAt()) ? stored.startedAt() : releasedAt));
    }

    @Override
    public synchronized PaymentIntent resolveAttempt(PaymentAttempt attempt, PaymentIntent intent,
            long expectedIntentVersion, String eventType, String correlationId) {
        List<PaymentAttempt> current = attempts.getOrDefault(attempt.intentId(), List.of());
        int index = -1;
        for (int candidate = 0; candidate < current.size(); candidate++) {
            if (current.get(candidate).id().equals(attempt.id())) {
                index = candidate;
                break;
            }
        }
        if (index < 0 || current.get(index).state().finalState()) {
            throw new PaymentCoreException("ATTEMPT_NOT_RESOLVABLE", "attempt is missing or final");
        }
        if (!sameLease(current.get(index), attempt)) {
            throw new PaymentCoreException("ATTEMPT_LEASE_LOST",
                    "attempt recovery lease is no longer owned by this worker");
        }
        PaymentIntent stored = requireIntent(intent.tenantId(), intent.id());
        if (stored.version() != expectedIntentVersion
                || (intent.version() != expectedIntentVersion
                    && intent.version() != expectedIntentVersion + 1)) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "payment intent changed during provider resolution");
        }
        current.set(index, attempt);
        intents.put(intent.id(), intent);
        return intent;
    }

    @Override
    public synchronized PaymentIntent resolveRecovery(PaymentAttempt originalAttempt,
            PaymentAttempt queryAttempt, PaymentIntent intent, long expectedIntentVersion,
            String eventType, String correlationId) {
        if (!originalAttempt.tenantId().equals(queryAttempt.tenantId())
                || !originalAttempt.intentId().equals(queryAttempt.intentId())
                || !intent.tenantId().equals(originalAttempt.tenantId())
                || !intent.id().equals(originalAttempt.intentId())) {
            throw new PaymentCoreException("RECOVERY_SCOPE_MISMATCH",
                    "recovery attempts must belong to the same tenant and intent");
        }
        List<PaymentAttempt> current = attempts.getOrDefault(intent.id(), List.of());
        int originalIndex = attemptIndex(current, originalAttempt.id());
        int queryIndex = attemptIndex(current, queryAttempt.id());
        if (originalIndex < 0 || current.get(originalIndex).operation() == AttemptOperation.QUERY
                || current.get(originalIndex).state().finalState()
                || queryIndex < 0 || current.get(queryIndex).state().finalState()) {
            throw new PaymentCoreException("ATTEMPT_NOT_RESOLVABLE",
                    "recovery source and query must be unresolved");
        }
        if (!sameLease(current.get(originalIndex), originalAttempt)
                || !sameLease(current.get(queryIndex), queryAttempt)) {
            throw new PaymentCoreException("ATTEMPT_LEASE_LOST",
                    "attempt recovery lease is no longer owned by this worker");
        }
        PaymentIntent stored = requireIntent(intent.tenantId(), intent.id());
        if (stored.version() != expectedIntentVersion
                || (intent.version() != expectedIntentVersion
                    && intent.version() != expectedIntentVersion + 1)) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "payment intent changed during provider recovery");
        }
        current.set(originalIndex, originalAttempt);
        current.set(queryIndex, queryAttempt);
        intents.put(intent.id(), intent);
        return intent;
    }

    @Override
    public synchronized List<PaymentAttempt> attempts(UUID tenantId, UUID intentId) {
        requireIntent(tenantId, intentId);
        return attempts.getOrDefault(intentId, List.of()).stream()
                .sorted(Comparator.comparingInt(PaymentAttempt::sequence)).toList();
    }

    private PaymentIntent requireIntent(UUID tenantId, UUID intentId) {
        return find(tenantId, intentId).orElseThrow(() -> new PaymentCoreException(
                "RESOURCE_NOT_FOUND", "payment intent does not exist in this tenant"));
    }

    private static int attemptIndex(List<PaymentAttempt> attempts, UUID attemptId) {
        for (int index = 0; index < attempts.size(); index++) {
            if (attempts.get(index).id().equals(attemptId)) {
                return index;
            }
        }
        return -1;
    }

    private static boolean sameLease(PaymentAttempt stored, PaymentAttempt proposed) {
        return stored.fencingToken() == proposed.fencingToken()
                && stored.leaseOwner().equals(proposed.leaseOwner());
    }

    private static void validateLease(String leaseOwner, Instant now, Instant leaseExpiresAt) {
        java.util.Objects.requireNonNull(leaseOwner, "leaseOwner");
        java.util.Objects.requireNonNull(now, "now");
        java.util.Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
        if (leaseOwner.isBlank() || leaseOwner.length() > 128 || !leaseExpiresAt.isAfter(now)) {
            throw new IllegalArgumentException("invalid payment attempt lease");
        }
    }

    private static void requireReceiptMatchesIntent(PaymentIntent intent,
            PaymentActionReceipt receipt) {
        if (!receipt.tenantId().equals(intent.tenantId())
                || !receipt.intentId().equals(intent.id())
                || receipt.resultIntentVersion() != intent.version()) {
            throw new PaymentCoreException("ACTION_RECEIPT_INVALID",
                    "action receipt does not match the resulting payment intent");
        }
    }

    private static void requireSameReceipt(PaymentActionReceipt existing,
            PaymentActionReceipt proposed) {
        if (!existing.matches(proposed.operation(), proposed.requestDigest())) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "action key was reused for a different operation or canonical payload");
        }
    }

    private record ReceiptKey(UUID tenantId, UUID intentId, String idempotencyKey) {
    }
}
