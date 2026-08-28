package com.elmpay.payment.checkout;

import java.time.Instant;
import java.util.UUID;

/** Durable payment-link persistence; bearer tokens themselves must never be stored. */
public interface PaymentLinkRepository {
    record Record(UUID id, UUID tenantId, UUID projectId, UUID checkoutSessionId,
            String tokenDigest, String signingKeyVersion, String idempotencyDigest,
            String requestDigest, Instant expiresAt, Instant consumedAt, Instant createdAt,
            long version) {}

    Record createOrGet(Record candidate);

    Record consume(UUID tenantId, String tokenDigest, Instant consumedAt);
}
