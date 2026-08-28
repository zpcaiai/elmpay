package com.elmpay.payment.checkout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

final class DurablePaymentLinkServiceTest {
    private static final UUID TENANT = UUID.fromString(
            "57000000-0000-4000-8000-000000000001");
    private static final UUID PROJECT = UUID.fromString(
            "57000000-0000-4000-8000-000000000002");
    private static final UUID SESSION = UUID.fromString(
            "57000000-0000-4000-8000-000000000003");
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");

    @Test
    void idempotentReplayReturnsExactTokenAndRepositoryNeverReceivesRawToken() {
        CapturingRepository repository = new CapturingRepository();
        DurablePaymentLinkService links = service(repository, NOW);

        DurablePaymentLinkService.Link first = links.create(TENANT, PROJECT, SESSION,
                Duration.ofMinutes(5), "create-link-1");
        DurablePaymentLinkService.Link replay = links.create(TENANT, PROJECT, SESSION,
                Duration.ofMinutes(5), "create-link-1");

        assertEquals(first.token(), replay.token());
        assertEquals(first.qrPayload(), replay.qrPayload());
        assertFalse(repository.last.tokenDigest().contains(first.token()));
        assertNotEquals(first.token(), repository.last.tokenDigest());
        assertEquals(64, repository.last.tokenDigest().length());
    }

    @Test
    void conflictingReplayAndInvalidTtlFailClosed() {
        DurablePaymentLinkService links = service(new InMemoryPaymentLinkRepository(), NOW);
        links.create(TENANT, PROJECT, SESSION, Duration.ofMinutes(5), "create-link-2");

        assertThrows(IllegalStateException.class, () -> links.create(TENANT, PROJECT,
                UUID.randomUUID(), Duration.ofMinutes(5), "create-link-2"));
        assertThrows(IllegalArgumentException.class, () -> links.create(TENANT, PROJECT,
                SESSION, Duration.ofMinutes(16), "too-long"));
    }

    @Test
    void signatureTamperingExpiryAndConcurrentReplayAreRejected() throws Exception {
        InMemoryPaymentLinkRepository repository = new InMemoryPaymentLinkRepository();
        DurablePaymentLinkService links = service(repository, NOW);
        DurablePaymentLinkService.Link link = links.create(TENANT, PROJECT, SESSION,
                Duration.ofMinutes(5), "create-link-3");
        String tampered = link.token().substring(0, link.token().length() - 1)
                + (link.token().endsWith("A") ? "B" : "A");
        assertThrows(SecurityException.class, () -> links.redeem(tampered));

        try (var executor = Executors.newFixedThreadPool(8)) {
            var work = java.util.stream.IntStream.range(0, 32)
                    .<Callable<Boolean>>mapToObj(ignored -> () -> {
                        try {
                            links.redeem(link.token());
                            return true;
                        } catch (SecurityException rejected) {
                            return false;
                        }
                    }).toList();
            long winners = executor.invokeAll(work).stream().filter(future -> {
                try {
                    return future.get();
                } catch (Exception failure) {
                    throw new AssertionError(failure);
                }
            }).count();
            assertEquals(1, winners);
        }

        DurablePaymentLinkService expired = service(new InMemoryPaymentLinkRepository(), NOW);
        DurablePaymentLinkService.Link shortLink = expired.create(TENANT, PROJECT, SESSION,
                Duration.ofSeconds(1), "create-link-expired");
        DurablePaymentLinkService afterExpiry = service(repositoryFrom(shortLink),
                NOW.plusSeconds(2));
        assertThrows(SecurityException.class, () -> afterExpiry.redeem(shortLink.token()));
    }

    @Test
    void unavailableSignerPreventsRuntimeConstruction() {
        PaymentLinkSigner unavailable = new PaymentLinkSigner() {
            @Override
            public Signature sign(byte[] canonicalPayload) {
                throw new IllegalStateException("unavailable");
            }

            @Override
            public String activeKeyVersion() {
                return "kms-v1";
            }

            @Override
            public boolean verify(String version, byte[] canonicalPayload, String signature) {
                return false;
            }

            @Override
            public boolean ready() {
                return false;
            }
        };
        assertThrows(IllegalStateException.class, () -> new DurablePaymentLinkService(
                new InMemoryPaymentLinkRepository(), unavailable, Clock.systemUTC()));
    }

    private static DurablePaymentLinkService service(PaymentLinkRepository repository,
            Instant now) {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x57);
        return new DurablePaymentLinkService(repository,
                new HmacPaymentLinkSigner(Map.of("kms-link-v1", key), "kms-link-v1"),
                Clock.fixed(now, ZoneOffset.UTC));
    }

    private static PaymentLinkRepository repositoryFrom(DurablePaymentLinkService.Link link) {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x57);
        PaymentLinkSigner signer = new HmacPaymentLinkSigner(Map.of("kms-link-v1", key),
                "kms-link-v1");
        String[] parts = link.token().split("\\.");
        PaymentLinkRepository.Record record = new PaymentLinkRepository.Record(
                UUID.fromString(parts[3]), TENANT, PROJECT, SESSION,
                sha256(link.token()), signer.activeKeyVersion(), sha256("create-link-expired"),
                sha256(TENANT + "\u0000" + PROJECT + "\u0000" + SESSION + "\u0000"
                        + Duration.ofSeconds(1).toNanos()),
                Instant.ofEpochMilli(Long.parseLong(parts[4])), null, NOW, 1);
        InMemoryPaymentLinkRepository repository = new InMemoryPaymentLinkRepository();
        repository.createOrGet(record);
        return repository;
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest
                    .getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new AssertionError(unavailable);
        }
    }

    private static final class CapturingRepository implements PaymentLinkRepository {
        private final InMemoryPaymentLinkRepository delegate = new InMemoryPaymentLinkRepository();
        private Record last;

        @Override
        public Record createOrGet(Record candidate) {
            last = candidate;
            return delegate.createOrGet(candidate);
        }

        @Override
        public Record consume(UUID tenantId, String tokenDigest, Instant consumedAt) {
            return delegate.consume(tenantId, tokenDigest, consumedAt);
        }
    }
}
