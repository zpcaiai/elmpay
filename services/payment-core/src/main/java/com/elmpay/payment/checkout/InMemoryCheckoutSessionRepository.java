package com.elmpay.payment.checkout;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Explicit local-sandbox repository; production runtimes must use a durable implementation. */
public final class InMemoryCheckoutSessionRepository implements CheckoutSessionRepository {
    private record Key(UUID tenantId, UUID projectId, String idempotencyKey) {
    }

    private record PaymentKey(UUID tenantId, UUID paymentIntentId) {
    }

    private final Map<String, Record> byId = new ConcurrentHashMap<>();
    private final Map<Key, Record> byCreateKey = new ConcurrentHashMap<>();
    private final Map<PaymentKey, Record> byPaymentIntent = new ConcurrentHashMap<>();

    @Override
    public Optional<Record> find(UUID tenantId, String sessionId) {
        Record value = byId.get(sessionId);
        return value != null && value.tenantId().equals(tenantId) ? Optional.of(value)
                : Optional.empty();
    }

    @Override
    public Optional<Record> findByCreateKey(UUID tenantId, UUID projectId, String idempotencyKey) {
        return Optional.ofNullable(byCreateKey.get(new Key(tenantId, projectId, idempotencyKey)));
    }

    @Override
    public synchronized Record createOrGet(Record candidate) {
        Key key = new Key(candidate.tenantId(), candidate.projectId(),
                candidate.createIdempotencyKey());
        Record winner = byCreateKey.get(key);
        if (winner != null) {
            return winner;
        }
        PaymentKey paymentKey = new PaymentKey(candidate.tenantId(),
                candidate.paymentIntentId());
        if (byId.containsKey(candidate.sessionId())) {
            throw new IllegalStateException("checkout session identifier collision");
        }
        if (byPaymentIntent.containsKey(paymentKey)) {
            throw new IllegalStateException("payment intent is already bound to a checkout session");
        }
        byId.put(candidate.sessionId(), candidate);
        byCreateKey.put(key, candidate);
        byPaymentIntent.put(paymentKey, candidate);
        return candidate;
    }
}
