package com.elmpay.audit;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Leased worker that persists only signature-verified external timestamp receipts. */
public final class AuditAnchorWorker {
    public enum Outcome { IDLE, ANCHORED, RETRY_SCHEDULED }

    public record Candidate(UUID anchorId, UUID tenantId, long throughSequence, String chainHash,
            long fencingToken, String workerId) {
        public Candidate {
            Objects.requireNonNull(anchorId, "anchorId");
            Objects.requireNonNull(tenantId, "tenantId");
            requirePositive(throughSequence, "throughSequence");
            requireSha256(chainHash, "chainHash");
            requirePositive(fencingToken, "fencingToken");
            requireId(workerId, "workerId");
        }
    }

    public record Receipt(String authorityId, String receiptId, UUID tenantId,
            long throughSequence, String chainHash, Instant anchoredAt, byte[] signature) {
        public Receipt {
            requireId(authorityId, "authorityId");
            requireId(receiptId, "receiptId");
            Objects.requireNonNull(tenantId, "tenantId");
            requirePositive(throughSequence, "throughSequence");
            requireSha256(chainHash, "chainHash");
            Objects.requireNonNull(anchoredAt, "anchoredAt");
            signature = Objects.requireNonNull(signature, "signature").clone();
            if (signature.length < 32 || signature.length > 512) {
                throw new IllegalArgumentException("signature has an invalid size");
            }
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    public interface Store {
        Optional<Candidate> claim(UUID tenantId, String workerId, Instant now, Instant leaseUntil);

        void recordVerifiedReceipt(Candidate candidate, Receipt receipt, Instant receivedAt);

        void recordFailure(Candidate candidate, String errorCode, Instant retryAt);
    }

    @FunctionalInterface
    public interface TimestampAuthority {
        Receipt anchor(Candidate candidate);
    }

    private final Store store;
    private final TimestampAuthority authority;
    private final PublicKey trustRoot;
    private final String workerId;
    private final Duration leaseDuration;
    private final Duration retryDelay;
    private final Duration maximumClockSkew;
    private final Clock clock;

    public AuditAnchorWorker(Store store, TimestampAuthority authority, PublicKey trustRoot,
            String workerId, Duration leaseDuration, Duration retryDelay,
            Duration maximumClockSkew, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.authority = Objects.requireNonNull(authority, "authority");
        this.trustRoot = Objects.requireNonNull(trustRoot, "trustRoot");
        requireId(workerId, "workerId");
        this.workerId = workerId;
        this.leaseDuration = positive(leaseDuration, "leaseDuration");
        this.retryDelay = positive(retryDelay, "retryDelay");
        this.maximumClockSkew = positive(maximumClockSkew, "maximumClockSkew");
        if (leaseDuration.compareTo(Duration.ofMinutes(5)) > 0
                || retryDelay.compareTo(Duration.ofHours(24)) > 0
                || maximumClockSkew.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("audit anchor timing exceeds policy bounds");
        }
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Outcome runOnce(UUID tenantId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Instant now = clock.instant();
        Optional<Candidate> claimed = store.claim(tenantId, workerId, now,
                now.plus(leaseDuration));
        if (claimed.isEmpty()) {
            return Outcome.IDLE;
        }
        Candidate candidate = claimed.orElseThrow();
        try {
            Receipt receipt = authority.anchor(candidate);
            verify(candidate, receipt, now);
            store.recordVerifiedReceipt(candidate, receipt, now);
            return Outcome.ANCHORED;
        } catch (RuntimeException exception) {
            store.recordFailure(candidate, failureCode(exception), now.plus(retryDelay));
            return Outcome.RETRY_SCHEDULED;
        }
    }

    private void verify(Candidate candidate, Receipt receipt, Instant receivedAt) {
        if (!candidate.tenantId().equals(receipt.tenantId())
                || candidate.throughSequence() != receipt.throughSequence()
                || !candidate.chainHash().equals(receipt.chainHash())) {
            throw new SecurityException("timestamp receipt is not bound to the claimed audit root");
        }
        if (receipt.anchoredAt().isAfter(receivedAt.plus(maximumClockSkew))
                || receipt.anchoredAt().isBefore(receivedAt.minus(maximumClockSkew))) {
            throw new SecurityException("timestamp receipt is outside the permitted clock window");
        }
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(trustRoot);
            verifier.update(canonicalReceipt(receipt));
            if (!verifier.verify(receipt.signature())) {
                throw new SecurityException("timestamp receipt signature is invalid");
            }
        } catch (GeneralSecurityException exception) {
            throw new SecurityException("timestamp receipt signature cannot be verified", exception);
        }
    }

    public static byte[] canonicalReceipt(Receipt receipt) {
        Objects.requireNonNull(receipt, "receipt");
        String value = "elmpay-audit-anchor-v1\n" + receipt.authorityId() + '\n'
                + receipt.receiptId() + '\n' + receipt.tenantId() + '\n'
                + receipt.throughSequence() + '\n' + receipt.chainHash() + '\n'
                + receipt.anchoredAt();
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String failureCode(RuntimeException exception) {
        String name = exception.getClass().getSimpleName().toUpperCase(java.util.Locale.ROOT);
        return name.length() <= 80 ? name : name.substring(0, 80);
    }

    private static Duration positive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }

    private static void requirePositive(long value, String field) {
        if (value <= 0) {
            throw new IllegalArgumentException(field + " must be positive");
        }
    }

    private static void requireSha256(String value, String field) {
        if (value == null || value.length() != 64) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
        try {
            HexFormat.of().parseHex(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(field + " has an invalid format", exception);
        }
    }

    private static void requireId(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{3,160}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }
}
