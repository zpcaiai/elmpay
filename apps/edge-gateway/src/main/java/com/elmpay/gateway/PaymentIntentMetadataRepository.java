package com.elmpay.gateway;

import java.util.Map;
import java.util.UUID;

/** Immutable, non-sensitive merchant metadata bound to a Payment Intent create request. */
public interface PaymentIntentMetadataRepository {
    void bind(UUID tenantId, UUID projectId, UUID paymentIntentId, String idempotencyKey,
            Map<String, String> metadata);

    Map<String, String> find(UUID tenantId, UUID paymentIntentId);
}
