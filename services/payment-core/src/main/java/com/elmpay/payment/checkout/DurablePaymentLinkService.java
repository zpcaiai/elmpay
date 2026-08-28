package com.elmpay.payment.checkout;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/** Durable, idempotent, short-lived and exactly-once B57 link/QR application service. */
public final class DurablePaymentLinkService {
    public record Link(String token, UUID checkoutSessionId, UUID tenantId, UUID projectId,
            Instant expiresAt, String qrPayload) {}
    public record Redemption(UUID tenantId, UUID projectId, UUID checkoutSessionId,
            Instant consumedAt) {}

    private final PaymentLinkRepository repository;
    private final PaymentLinkSigner signer;
    private final Clock clock;

    public DurablePaymentLinkService(PaymentLinkRepository repository, PaymentLinkSigner signer,
            Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.signer = Objects.requireNonNull(signer, "signer");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (!signer.ready() || signer.activeKeyVersion() == null
                || signer.activeKeyVersion().isBlank()) {
            throw new IllegalStateException("payment-link signer is not ready");
        }
    }

    public Link create(UUID tenantId, UUID projectId, UUID checkoutSessionId, Duration ttl,
            String idempotencyKey) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(checkoutSessionId, "checkoutSessionId");
        if (ttl == null || ttl.isNegative() || ttl.isZero()
                || ttl.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException("payment-link TTL must be 1ns-15m");
        }
        String idempotencyDigest = digest(required(idempotencyKey, "idempotencyKey"));
        String requestDigest = digest(tenantId + "\u0000" + projectId + "\u0000"
                + checkoutSessionId + "\u0000" + ttl.toNanos());
        UUID candidateId = UUID.randomUUID();
        Instant now = clock.instant();
        PaymentLinkRepository.Record candidate = unsignedRecord(candidateId, tenantId, projectId,
                checkoutSessionId, idempotencyDigest, requestDigest, now.plus(ttl), now);
        String candidateToken = token(candidate, idempotencyDigest);
        candidate = new PaymentLinkRepository.Record(candidate.id(), candidate.tenantId(),
                candidate.projectId(), candidate.checkoutSessionId(), digest(candidateToken),
                candidate.signingKeyVersion(), candidate.idempotencyDigest(),
                candidate.requestDigest(), candidate.expiresAt(), null, candidate.createdAt(), 1);
        PaymentLinkRepository.Record stored = repository.createOrGet(candidate);
        String replayToken = token(stored, idempotencyDigest);
        if (!MessageDigest.isEqual(digest(replayToken).getBytes(StandardCharsets.US_ASCII),
                stored.tokenDigest().getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("payment-link replay token digest mismatch");
        }
        return new Link(replayToken, stored.checkoutSessionId(), stored.tenantId(),
                stored.projectId(), stored.expiresAt(), "/checkout/link/" + replayToken);
    }

    public Redemption redeem(String token) {
        Parsed parsed = parse(token);
        if (!signer.verify(parsed.keyVersion(), parsed.payload().getBytes(StandardCharsets.UTF_8),
                parsed.signature())) {
            throw new SecurityException("invalid payment-link signature");
        }
        PaymentLinkRepository.Record consumed = repository.consume(parsed.tenantId(),
                digest(token), clock.instant());
        if (!consumed.id().equals(parsed.linkId())
                || !consumed.signingKeyVersion().equals(parsed.keyVersion())) {
            throw new SecurityException("payment-link identity mismatch");
        }
        return new Redemption(consumed.tenantId(), consumed.projectId(),
                consumed.checkoutSessionId(), consumed.consumedAt());
    }

    private PaymentLinkRepository.Record unsignedRecord(UUID id, UUID tenantId, UUID projectId,
            UUID sessionId, String idempotencyDigest, String requestDigest, Instant expiresAt,
            Instant createdAt) {
        return new PaymentLinkRepository.Record(id, tenantId, projectId, sessionId, "0".repeat(64),
                signer.activeKeyVersion(), idempotencyDigest, requestDigest, expiresAt, null,
                createdAt, 1);
    }

    private String token(PaymentLinkRepository.Record record, String idempotencyDigest) {
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(
                idempotencyDigest.substring(0, 32).getBytes(StandardCharsets.US_ASCII));
        String payload = "v1." + record.signingKeyVersion() + "." + record.tenantId() + "."
                + record.id() + "." + record.expiresAt().toEpochMilli() + "." + nonce;
        PaymentLinkSigner.Signature signature = signer.sign(
                payload.getBytes(StandardCharsets.UTF_8));
        if (!record.signingKeyVersion().equals(signature.keyVersion())) {
            throw new IllegalStateException("payment-link active signing key changed mid-operation");
        }
        return payload + "." + signature.value();
    }

    private static Parsed parse(String token) {
        if (token == null || token.length() > 2_048) {
            throw new SecurityException("invalid payment-link token");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 7 || !"v1".equals(parts[0])) {
            throw new SecurityException("invalid payment-link token");
        }
        try {
            String payload = String.join(".", java.util.Arrays.copyOf(parts, 6));
            return new Parsed(parts[1], UUID.fromString(parts[2]), UUID.fromString(parts[3]),
                    Instant.ofEpochMilli(Long.parseLong(parts[4])), payload, parts[6]);
        } catch (IllegalArgumentException invalid) {
            throw new SecurityException("invalid payment-link token", invalid);
        }
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("JDK is missing SHA-256", unavailable);
        }
    }

    private static String required(String value, String label) {
        if (value == null || value.isBlank() || value.length() > 200) {
            throw new IllegalArgumentException(label + " is required and bounded");
        }
        return value;
    }

    private record Parsed(String keyVersion, UUID tenantId, UUID linkId, Instant expiresAt,
            String payload, String signature) {}
}
