package com.elmpay.tenant;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Verifies exact, short-lived tenant authority receipts against pinned Ed25519 trust roots. */
public final class TenantEvidenceVerifier {
    private static final byte[] DOMAIN =
            "ELMPAY-TENANT-AUTHORITY-EVIDENCE-V1".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern IDENTITY =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}");
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

    @FunctionalInterface
    public interface ReplayGuard {
        /** Accepts a new nonce or an exact idempotent replay; rejects mutated nonce reuse. */
        boolean accept(AuthorityEvidenceReceipt receipt, String receiptDigest,
                Instant acceptedAt);
    }

    public record TrustKey(PublicKey publicKey, String signerIdentity, String authority,
            Set<TenantEvidenceType> evidenceTypes, Instant notBefore, Instant notAfter,
            boolean revoked) {
        public TrustKey {
            Objects.requireNonNull(publicKey, "publicKey");
            signerIdentity = required(signerIdentity, "signerIdentity");
            authority = required(authority, "authority");
            evidenceTypes = Set.copyOf(Objects.requireNonNull(evidenceTypes, "evidenceTypes"));
            Objects.requireNonNull(notBefore, "notBefore");
            Objects.requireNonNull(notAfter, "notAfter");
            if ((!"EdDSA".equals(publicKey.getAlgorithm())
                    && !"Ed25519".equals(publicKey.getAlgorithm()))
                    || !IDENTITY.matcher(signerIdentity).matches()
                    || !IDENTITY.matcher(authority).matches() || evidenceTypes.isEmpty()
                    || evidenceTypes.contains(TenantEvidenceType.UNKNOWN)
                    || !notAfter.isAfter(notBefore)) {
                throw new IllegalArgumentException("tenant evidence trust key is invalid");
            }
        }
    }

    private final Map<String, TrustKey> keys;
    private final ReplayGuard replayGuard;
    private final Duration maximumLifetime;
    private final Duration clockSkew;

    public TenantEvidenceVerifier(Map<String, TrustKey> keys, ReplayGuard replayGuard,
            Duration maximumLifetime, Duration clockSkew) {
        this.keys = Map.copyOf(Objects.requireNonNull(keys, "keys"));
        this.replayGuard = Objects.requireNonNull(replayGuard, "replayGuard");
        if (this.keys.isEmpty() || maximumLifetime == null || maximumLifetime.isZero()
                || maximumLifetime.isNegative()
                || maximumLifetime.compareTo(Duration.ofMinutes(10)) > 0
                || clockSkew == null || clockSkew.isNegative()
                || clockSkew.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("tenant evidence verifier policy is invalid");
        }
        if (this.keys.entrySet().stream().anyMatch(entry -> entry.getKey() == null
                || !KEY_ID.matcher(entry.getKey()).matches() || entry.getValue() == null)) {
            throw new IllegalArgumentException("tenant evidence trust key map is invalid");
        }
        this.maximumLifetime = maximumLifetime;
        this.clockSkew = clockSkew;
    }

    public VerifiedTenantEvidence verify(AuthorityEvidenceReceipt receipt, UUID expectedTenantId,
            TenantEvidenceType expectedType, Instant now) {
        Objects.requireNonNull(receipt, "authority evidence receipt");
        Objects.requireNonNull(expectedTenantId, "expectedTenantId");
        Objects.requireNonNull(expectedType, "expectedType");
        Objects.requireNonNull(now, "now");
        if (expectedType == TenantEvidenceType.UNKNOWN
                || !expectedTenantId.equals(receipt.tenantId())
                || expectedType != receipt.evidenceType()) {
            throw new SecurityException("tenant authority evidence binding mismatch");
        }
        TrustKey key = keys.get(receipt.keyId());
        if (key == null || key.revoked() || !key.evidenceTypes().contains(expectedType)
                || !key.authority().equals(receipt.authority())
                || now.isBefore(key.notBefore()) || !now.isBefore(key.notAfter())
                || receipt.issuedAt().isBefore(key.notBefore())
                || receipt.expiresAt().isAfter(key.notAfter())) {
            throw new SecurityException("tenant authority evidence signer is not trusted");
        }
        if (receipt.issuedAt().isAfter(now.plus(clockSkew))
                || !receipt.expiresAt().isAfter(now)
                || !receipt.expiresAt().isAfter(receipt.issuedAt())
                || Duration.between(receipt.issuedAt(), receipt.expiresAt())
                        .compareTo(maximumLifetime) > 0) {
            throw new SecurityException("tenant authority evidence time window is invalid");
        }
        byte[] payload = signaturePayload(receipt);
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key.publicKey());
            verifier.update(payload);
            if (!verifier.verify(receipt.signature())) {
                throw new SecurityException("tenant authority evidence signature is invalid");
            }
        } catch (GeneralSecurityException unavailable) {
            throw new SecurityException("tenant authority evidence verification is unavailable",
                    unavailable);
        }
        String receiptDigest = digest(payload, receipt.signature());
        if (!replayGuard.accept(receipt, receiptDigest, now)) {
            throw new SecurityException("tenant authority evidence nonce was reused");
        }
        return new VerifiedTenantEvidence(receipt.tenantId(), receipt.evidenceType(),
                receipt.authority(), receipt.decisionReference(), receipt.payloadDigest(),
                receiptDigest, key.signerIdentity(), receipt.keyId(), receipt.issuedAt(),
                receipt.expiresAt());
    }

    public static byte[] signaturePayload(AuthorityEvidenceReceipt receipt) {
        Objects.requireNonNull(receipt, "receipt");
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                write(output, DOMAIN);
                write(output, receipt.tenantId().toString());
                write(output, receipt.evidenceType().name());
                write(output, receipt.authority());
                write(output, receipt.decisionReference());
                write(output, receipt.payloadDigest());
                write(output, receipt.issuedAt().toString());
                write(output, receipt.expiresAt().toString());
                write(output, receipt.nonce());
                write(output, receipt.keyId());
            }
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory tenant evidence encoding failed",
                    impossible);
        }
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        write(output, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void write(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static String digest(byte[] payload, byte[] signature) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(payload);
            digest.update(signature);
            return HexFormat.of().formatHex(digest.digest());
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw new IllegalArgumentException(field + " is required and bounded");
        }
        return value;
    }
}
