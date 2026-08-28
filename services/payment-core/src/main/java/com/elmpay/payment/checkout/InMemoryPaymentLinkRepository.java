package com.elmpay.payment.checkout;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Explicit local/test repository with the same idempotency and one-time rules as PostgreSQL. */
public final class InMemoryPaymentLinkRepository implements PaymentLinkRepository {
    private final Map<String, Record> idempotency = new ConcurrentHashMap<>();
    private final Map<String, Record> tokens = new ConcurrentHashMap<>();

    @Override
    public synchronized Record createOrGet(Record candidate) {
        String key = candidate.tenantId() + "\u0000" + candidate.projectId() + "\u0000"
                + candidate.idempotencyDigest();
        Record existing = idempotency.get(key);
        if (existing != null) {
            if (!java.security.MessageDigest.isEqual(existing.requestDigest().getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII), candidate.requestDigest().getBytes(
                            java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new IllegalStateException("payment-link idempotency conflict");
            }
            return existing;
        }
        idempotency.put(key, candidate);
        tokens.put(candidate.tenantId() + "\u0000" + candidate.tokenDigest(), candidate);
        return candidate;
    }

    @Override
    public synchronized Record consume(UUID tenantId, String tokenDigest, Instant consumedAt) {
        String key = tenantId + "\u0000" + tokenDigest;
        Record current = tokens.get(key);
        if (current == null || current.consumedAt() != null
                || !consumedAt.isBefore(current.expiresAt())) {
            throw new SecurityException("payment link is unknown, expired, or already consumed");
        }
        Record updated = new Record(current.id(), current.tenantId(), current.projectId(),
                current.checkoutSessionId(), current.tokenDigest(), current.signingKeyVersion(),
                current.idempotencyDigest(), current.requestDigest(), current.expiresAt(),
                consumedAt, current.createdAt(), current.version() + 1);
        tokens.put(key, updated);
        idempotency.replaceAll((ignored, value) -> value.id().equals(updated.id())
                ? updated : value);
        return updated;
    }
}
