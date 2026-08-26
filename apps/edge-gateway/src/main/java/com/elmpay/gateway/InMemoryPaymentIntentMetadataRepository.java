package com.elmpay.gateway;

import com.elmpay.payment.PaymentCoreException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryPaymentIntentMetadataRepository
        implements PaymentIntentMetadataRepository {
    private final ConcurrentHashMap<Key, Binding> values = new ConcurrentHashMap<>();

    @Override
    public void bind(UUID tenantId, UUID projectId, UUID paymentIntentId, String idempotencyKey,
            Map<String, String> metadata) {
        Binding candidate = new Binding(projectId, idempotencyKey, metadata);
        Binding existing = values.putIfAbsent(new Key(tenantId, paymentIntentId), candidate);
        if (existing != null && !existing.equals(candidate)) {
            throw conflict();
        }
    }

    @Override
    public Map<String, String> find(UUID tenantId, UUID paymentIntentId) {
        Binding value = values.get(new Key(tenantId, paymentIntentId));
        return value == null ? Map.of() : value.metadata();
    }

    static PaymentCoreException conflict() {
        return new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                "payment intent metadata differs from the original create request");
    }

    private record Key(UUID tenantId, UUID paymentIntentId) {
        private Key {
            java.util.Objects.requireNonNull(tenantId, "tenantId");
            java.util.Objects.requireNonNull(paymentIntentId, "paymentIntentId");
        }
    }

    private record Binding(UUID projectId, String idempotencyKey, Map<String, String> metadata) {
        private Binding {
            java.util.Objects.requireNonNull(projectId, "projectId");
            java.util.Objects.requireNonNull(idempotencyKey, "idempotencyKey");
            metadata = Map.copyOf(metadata);
        }
    }
}
