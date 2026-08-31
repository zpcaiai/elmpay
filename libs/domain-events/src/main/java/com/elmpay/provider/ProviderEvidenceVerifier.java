package com.elmpay.provider;

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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Verifies exact, short-lived Ed25519 receipts from provider verifier/query workloads. */
public final class ProviderEvidenceVerifier {
    private static final byte[] DOMAIN =
            "ELMPAY-PROVIDER-EVIDENCE-V1".getBytes(StandardCharsets.US_ASCII);

    @FunctionalInterface
    public interface ReplayGuard {
        /** Accepts a new nonce or an exact idempotent replay; rejects mutated nonce reuse. */
        boolean accept(ProviderEvidenceReceipt receipt, String receiptDigest, Instant acceptedAt);
    }

    public record TrustKey(PublicKey publicKey, String identity, String provider,
            Set<String> evidenceTypes, Instant notBefore, Instant notAfter, boolean revoked) {
        public TrustKey {
            Objects.requireNonNull(publicKey, "publicKey");
            identity = required(identity, "identity");
            provider = required(provider, "provider");
            evidenceTypes = Set.copyOf(Objects.requireNonNull(evidenceTypes, "evidenceTypes"));
            Objects.requireNonNull(notBefore, "notBefore");
            Objects.requireNonNull(notAfter, "notAfter");
            if (evidenceTypes.isEmpty() || !notAfter.isAfter(notBefore)) {
                throw new IllegalArgumentException("provider evidence trust key is invalid");
            }
        }
    }

    private final Map<String, TrustKey> keys;
    private final ReplayGuard replayGuard;
    private final Duration maximumLifetime;
    private final Duration clockSkew;

    public ProviderEvidenceVerifier(Map<String, TrustKey> keys, ReplayGuard replayGuard,
            Duration maximumLifetime, Duration clockSkew) {
        this.keys = Map.copyOf(Objects.requireNonNull(keys, "keys"));
        this.replayGuard = Objects.requireNonNull(replayGuard, "replayGuard");
        if (this.keys.isEmpty() || maximumLifetime == null || maximumLifetime.isZero()
                || maximumLifetime.isNegative() || maximumLifetime.compareTo(
                        Duration.ofMinutes(10)) > 0 || clockSkew == null
                || clockSkew.isNegative() || clockSkew.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("provider evidence verifier policy is invalid");
        }
        this.maximumLifetime = maximumLifetime;
        this.clockSkew = clockSkew;
    }

    public VerifiedProviderEvidence verify(ProviderEvidenceReceipt receipt,
            String expectedType, Map<String, String> expectedFields, Instant now) {
        Objects.requireNonNull(receipt, "provider evidence receipt");
        Objects.requireNonNull(now, "now");
        Map<String, String> fields = Map.copyOf(Objects.requireNonNull(expectedFields,
                "expectedFields"));
        if (!expectedType.equals(receipt.evidenceType()) || !fields.equals(receipt.fields())) {
            throw new SecurityException("provider evidence binding mismatch");
        }
        TrustKey key = keys.get(receipt.keyId());
        if (key == null || key.revoked() || !key.evidenceTypes().contains(expectedType)
                || !key.provider().equals(fields.get("provider"))
                || now.isBefore(key.notBefore()) || !now.isBefore(key.notAfter())
                || receipt.issuedAt().isBefore(key.notBefore())
                || receipt.expiresAt().isAfter(key.notAfter())) {
            throw new SecurityException("provider evidence signer is not trusted");
        }
        if (receipt.issuedAt().isAfter(now.plus(clockSkew))
                || !receipt.expiresAt().isAfter(now.minus(clockSkew))
                || !receipt.expiresAt().isAfter(receipt.issuedAt())
                || Duration.between(receipt.issuedAt(), receipt.expiresAt())
                        .compareTo(maximumLifetime) > 0) {
            throw new SecurityException("provider evidence time window is invalid");
        }
        byte[] payload = signaturePayload(receipt);
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key.publicKey());
            verifier.update(payload);
            if (!verifier.verify(receipt.signature())) {
                throw new SecurityException("provider evidence signature is invalid");
            }
        } catch (GeneralSecurityException unavailable) {
            throw new SecurityException("provider evidence verification is unavailable",
                    unavailable);
        }
        String digest = digest(payload, receipt.signature());
        if (!replayGuard.accept(receipt, digest, now)) {
            throw new SecurityException("provider evidence nonce was reused");
        }
        return new VerifiedProviderEvidence(expectedType, fields, digest, key.identity());
    }

    public static byte[] signaturePayload(ProviderEvidenceReceipt receipt) {
        Objects.requireNonNull(receipt, "receipt");
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                write(output, DOMAIN);
                write(output, receipt.evidenceType());
                List<Map.Entry<String, String>> fields = new ArrayList<>(
                        receipt.fields().entrySet());
                fields.sort(Comparator.comparing(Map.Entry::getKey));
                output.writeInt(fields.size());
                for (Map.Entry<String, String> field : fields) {
                    write(output, field.getKey());
                    write(output, field.getValue());
                }
                write(output, receipt.keyId());
                write(output, receipt.issuedAt().toString());
                write(output, receipt.expiresAt().toString());
                write(output, receipt.nonce());
            }
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory provider evidence encoding failed",
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
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
