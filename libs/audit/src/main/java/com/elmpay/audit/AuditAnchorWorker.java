package com.elmpay.audit;

import com.elmpay.security.MountedHttpsClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

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

    /**
     * Fully mounted production composition. Construction validates mTLS, the rotating token and
     * the exact Ed25519 receipt-verification public key before returning a worker.
     */
    public static AuditAnchorWorker fromEnvironment(DataSource dataSource,
            Map<String, String> environment, Clock clock) {
        Objects.requireNonNull(dataSource, "dataSource");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(clock, "clock");
        HttpsAuditTimestampAuthority authority =
                HttpsAuditTimestampAuthority.fromEnvironment(environment, clock);
        byte[] encodedTrust = MountedHttpsClient.readExactMountedFile(environment,
                "ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_RECEIPT_PUBLIC_KEY_FILE",
                "audit-timestamp-client", "receipt-public-key.pem", 16 * 1024);
        try {
            PublicKey trust = ed25519PublicKey(encodedTrust);
            return new AuditAnchorWorker(new JdbcAuditAnchorStore(dataSource), authority, trust,
                    required(environment, "ELMPAY_AUDIT_ANCHOR_WORKER_ID"),
                    duration(environment, "ELMPAY_AUDIT_ANCHOR_LEASE_MILLISECONDS", 30_000,
                            300_000),
                    duration(environment, "ELMPAY_AUDIT_ANCHOR_RETRY_MILLISECONDS", 60_000,
                            86_400_000),
                    duration(environment, "ELMPAY_AUDIT_ANCHOR_MAX_CLOCK_SKEW_MILLISECONDS",
                            30_000, 300_000), clock);
        } finally {
            Arrays.fill(encodedTrust, (byte) 0);
        }
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
            byte[] canonical = canonicalReceipt(receipt);
            byte[] signature = receipt.signature();
            try {
                verifier.update(canonical);
                if (!verifier.verify(signature)) {
                    throw new SecurityException("timestamp receipt signature is invalid");
                }
            } finally {
                Arrays.fill(canonical, (byte) 0);
                Arrays.fill(signature, (byte) 0);
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

    static PublicKey ed25519PublicKey(byte[] raw) {
        byte[] begin = "-----BEGIN PUBLIC KEY-----".getBytes(StandardCharsets.US_ASCII);
        byte[] end = "-----END PUBLIC KEY-----".getBytes(StandardCharsets.US_ASCII);
        int start = skipLineWhitespace(raw, 0);
        int footer = find(raw, end, start + begin.length);
        if (!matches(raw, start, begin) || footer < start + begin.length
                || find(raw, begin, start + begin.length) >= 0
                || find(raw, end, footer + end.length) >= 0
                || skipLineWhitespace(raw, footer + end.length) != raw.length) {
            throw new SecurityException(
                    "timestamp receipt trust key must be one X.509 Ed25519 public key");
        }
        int encodedLength = 0;
        for (int index = start + begin.length; index < footer; index++) {
            byte value = raw[index];
            if (value == '\r' || value == '\n') {
                continue;
            }
            if (!base64(value)) {
                throw new SecurityException("timestamp receipt trust key PEM is invalid");
            }
            encodedLength = Math.addExact(encodedLength, 1);
        }
        if (encodedLength < 4 || encodedLength > 8 * 1024 || encodedLength % 4 != 0) {
            throw new SecurityException("timestamp receipt trust key PEM is invalid");
        }
        byte[] normalized = new byte[encodedLength];
        byte[] der = null;
        try {
            int target = 0;
            for (int index = start + begin.length; index < footer; index++) {
                byte value = raw[index];
                if (value != '\r' && value != '\n') {
                    normalized[target++] = value;
                }
            }
            der = Base64.getDecoder().decode(normalized);
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (!Set.of("Ed25519", "EdDSA").contains(key.getAlgorithm())) {
                throw new SecurityException("timestamp receipt trust key is not Ed25519");
            }
            byte[] canonical = key.getEncoded();
            try {
                if (canonical == null || !java.security.MessageDigest.isEqual(der, canonical)) {
                    throw new SecurityException(
                            "timestamp receipt trust key encoding is not canonical");
                }
            } finally {
                if (canonical != null) {
                    Arrays.fill(canonical, (byte) 0);
                }
            }
            return key;
        } catch (GeneralSecurityException | IllegalArgumentException failure) {
            throw new SecurityException("timestamp receipt trust key is invalid", failure);
        } finally {
            Arrays.fill(normalized, (byte) 0);
            if (der != null) {
                Arrays.fill(der, (byte) 0);
            }
        }
    }

    private static Duration duration(Map<String, String> environment, String key,
            long fallback, long maximum) {
        String configured = environment.get(key);
        long value = fallback;
        if (configured != null) {
            if (!configured.matches("(?:0|[1-9][0-9]{0,8})")) {
                throw new IllegalStateException(key + " is invalid");
            }
            value = Long.parseLong(configured);
        }
        if (value < 1 || value > maximum) {
            throw new IllegalStateException(key + " exceeds its production bound");
        }
        return Duration.ofMillis(value);
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }

    private static int skipLineWhitespace(byte[] value, int start) {
        int index = start;
        while (index < value.length && (value[index] == '\r' || value[index] == '\n')) {
            index++;
        }
        return index;
    }

    private static boolean matches(byte[] value, int offset, byte[] expected) {
        if (offset < 0 || value.length - offset < expected.length) {
            return false;
        }
        for (int index = 0; index < expected.length; index++) {
            if (value[offset + index] != expected[index]) {
                return false;
            }
        }
        return true;
    }

    private static int find(byte[] value, byte[] expected, int start) {
        for (int index = Math.max(start, 0); index <= value.length - expected.length; index++) {
            if (matches(value, index, expected)) {
                return index;
            }
        }
        return -1;
    }

    private static boolean base64(byte value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
                || value >= '0' && value <= '9' || value == '+' || value == '/'
                || value == '=';
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
