package com.elmpay.payment.checkout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class CheckoutPersistenceTest {
    private static final UUID TENANT = UUID.fromString(
            "10000000-0000-4000-8000-000000000001");

    @Test
    void signingTokenIsRecreatedAfterRestartAndTamperingFails() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 7);
        CheckoutSessionRepository.Record record = record("10000000-0000-4000-8000-000000000005");
        String token = new CheckoutTokenSigner(Map.of("key-v1", key), "key-v1").token(record);
        CheckoutTokenSigner afterRestart = new CheckoutTokenSigner(Map.of("key-v1", key),
                "key-v1");
        assertEquals(TENANT, afterRestart.tenantClaim(token));
        assertTrue(afterRestart.verify(record, token));
        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("A") ? "B" : "A");
        assertFalse(afterRestart.verify(record, tampered));
        assertFalse(record.toString().contains(token), "raw browser bearer must not be persisted");
    }

    @Test
    void concurrentLocalCreatesHaveOneIdempotentWinner() throws Exception {
        InMemoryCheckoutSessionRepository repository = new InMemoryCheckoutSessionRepository();
        try (var executor = Executors.newFixedThreadPool(8)) {
            var tasks = java.util.stream.IntStream.range(0, 32)
                    .<Callable<CheckoutSessionRepository.Record>>mapToObj(index ->
                            () -> repository.createOrGet(record(UUID.randomUUID().toString())))
                    .toList();
            Set<String> winners = executor.invokeAll(tasks).stream().map(future -> {
                try {
                    return future.get().sessionId();
                } catch (Exception failure) {
                    throw new AssertionError(failure);
                }
            }).collect(java.util.stream.Collectors.toSet());
            assertEquals(1, winners.size());
        }
    }

    @Test
    void localRepositoryEnforcesOneSessionPerPaymentIntent() {
        InMemoryCheckoutSessionRepository repository = new InMemoryCheckoutSessionRepository();
        CheckoutSessionRepository.Record first = record(
                "10000000-0000-4000-8000-000000000005");
        repository.createOrGet(first);
        CheckoutSessionRepository.Record conflicting = new CheckoutSessionRepository.Record(
                "10000000-0000-4000-8000-000000000006", first.tenantId(), first.projectId(),
                first.merchantId(), first.paymentIntentId(), first.businessOrderNo(),
                first.amountMinor(), first.currency(), first.returnRouteId(), first.returnUri(),
                first.deviceContextDigest(), first.expiresAt(), first.keyId(), "B".repeat(43),
                first.allowedMethods(), "checkout-idem-0002", "b".repeat(64), first.createdAt());
        assertThrows(IllegalStateException.class, () -> repository.createOrGet(conflicting));
    }

    @Test
    void persistedClaimsRejectInvalidMoneyAndNormalizeTheReturnOrigin() {
        CheckoutSessionRepository.Record normalized = new CheckoutSessionRepository.Record(
                "10000000-0000-4000-8000-000000000006", TENANT,
                UUID.fromString("10000000-0000-4000-8000-000000000002"),
                UUID.fromString("10000000-0000-4000-8000-000000000003"),
                UUID.fromString("10000000-0000-4000-8000-000000000006"), "order-2", 100,
                "USD", "checkout-complete", URI.create("HTTPS://MERCHANT.EXAMPLE/complete"),
                "device-context-not-provided", Instant.parse("2026-08-26T00:10:00Z"),
                "key-v1", "C".repeat(43), Set.of("CARD"), "checkout-idem-0003",
                "c".repeat(64), Instant.parse("2026-08-26T00:00:00Z"));
        assertEquals("https://merchant.example/complete", normalized.returnUri().toString());
        assertEquals(Set.of("card"), normalized.allowedMethods());
        assertThrows(IllegalArgumentException.class, () -> new CheckoutSessionRepository.Record(
                normalized.sessionId(), normalized.tenantId(), normalized.projectId(),
                normalized.merchantId(), normalized.paymentIntentId(), normalized.businessOrderNo(),
                0, normalized.currency(), normalized.returnRouteId(), normalized.returnUri(),
                normalized.deviceContextDigest(), normalized.expiresAt(), normalized.keyId(),
                normalized.nonce(), normalized.allowedMethods(), normalized.createIdempotencyKey(),
                normalized.requestDigest(), normalized.createdAt()));
    }

    private static CheckoutSessionRepository.Record record(String sessionId) {
        Instant created = Instant.parse("2026-08-26T00:00:00Z");
        return new CheckoutSessionRepository.Record(sessionId, TENANT,
                UUID.fromString("10000000-0000-4000-8000-000000000002"),
                UUID.fromString("10000000-0000-4000-8000-000000000003"),
                UUID.fromString("10000000-0000-4000-8000-000000000004"), "order-1", 100,
                "USD", "checkout-complete", URI.create("https://merchant.example/complete"),
                "device-context-not-provided", created.plusSeconds(600), "key-v1",
                "A".repeat(43), Set.of("card"), "checkout-idem-0001", "a".repeat(64), created);
    }
}
