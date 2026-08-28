package com.elmpay.security;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM envelope encryption with tenant/resource/purpose-bound AAD. */
public final class EnvelopeEncryptionService {
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    public record Envelope(String keyReference, String keyVersion, byte[] wrappedDataKey,
            byte[] nonce, byte[] ciphertext, byte[] aadDigest, Instant createdAt) {
        public Envelope {
            requireText(keyReference, "keyReference");
            requireText(keyVersion, "keyVersion");
            wrappedDataKey = wrappedDataKey.clone();
            nonce = nonce.clone();
            ciphertext = ciphertext.clone();
            aadDigest = aadDigest.clone();
            if (wrappedDataKey.length < KEY_BYTES || nonce.length != NONCE_BYTES
                    || ciphertext.length < 16 || aadDigest.length != 32 || createdAt == null) {
                throw new IllegalArgumentException("encrypted envelope is malformed");
            }
        }

        @Override public byte[] wrappedDataKey() { return wrappedDataKey.clone(); }
        @Override public byte[] nonce() { return nonce.clone(); }
        @Override public byte[] ciphertext() { return ciphertext.clone(); }
        @Override public byte[] aadDigest() { return aadDigest.clone(); }
    }

    private final KmsClient kms;
    private final Clock clock;
    private final SecureRandom random;
    private final Duration maximumPlaintextKeyLifetime;

    public EnvelopeEncryptionService(KmsClient kms, Clock clock, SecureRandom random,
            Duration maximumPlaintextKeyLifetime) {
        this.kms = Objects.requireNonNull(kms, "kms");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.maximumPlaintextKeyLifetime = Objects.requireNonNull(maximumPlaintextKeyLifetime,
                "maximumPlaintextKeyLifetime");
        if (maximumPlaintextKeyLifetime.isZero() || maximumPlaintextKeyLifetime.isNegative()
                || maximumPlaintextKeyLifetime.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("plaintext data-key lifetime must be 1..30 seconds");
        }
    }

    public Envelope encrypt(String keyReference, byte[] plaintext, Map<String, String> aad) {
        Objects.requireNonNull(plaintext, "plaintext");
        if (plaintext.length == 0 || plaintext.length > 1_048_576) {
            throw new IllegalArgumentException("plaintext size is outside 1..1048576 bytes");
        }
        byte[] encodedAad = canonicalAad(aad);
        KmsClient.GeneratedDataKey generated = kms.generateDataKey(keyReference,
                Map.copyOf(aad), maximumPlaintextKeyLifetime);
        byte[] dataKey = generated.plaintextKey();
        try {
            requireFresh(generated.plaintextExpiresAt());
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            byte[] encrypted = crypt(Cipher.ENCRYPT_MODE, dataKey, nonce, encodedAad, plaintext);
            return new Envelope(generated.keyReference(), generated.keyVersion(),
                    generated.wrappedDataKey(), nonce, encrypted, sha256(encodedAad), clock.instant());
        } finally {
            Arrays.fill(dataKey, (byte) 0);
            Arrays.fill(encodedAad, (byte) 0);
        }
    }

    public byte[] decrypt(Envelope envelope, Map<String, String> aad) {
        Objects.requireNonNull(envelope, "envelope");
        byte[] encodedAad = canonicalAad(aad);
        if (!MessageDigest.isEqual(envelope.aadDigest(), sha256(encodedAad))) {
            Arrays.fill(encodedAad, (byte) 0);
            throw new SecurityException("envelope AAD does not match tenant/resource/purpose");
        }
        KmsClient.UnwrappedDataKey unwrapped = kms.unwrapDataKey(envelope.keyReference(),
                envelope.keyVersion(), envelope.wrappedDataKey(), Map.copyOf(aad),
                maximumPlaintextKeyLifetime);
        byte[] dataKey = unwrapped.plaintextKey();
        try {
            requireFresh(unwrapped.plaintextExpiresAt());
            return crypt(Cipher.DECRYPT_MODE, dataKey, envelope.nonce(), encodedAad,
                    envelope.ciphertext());
        } catch (SecurityException exception) {
            throw exception;
        } finally {
            Arrays.fill(dataKey, (byte) 0);
            Arrays.fill(encodedAad, (byte) 0);
        }
    }

    public Envelope rotate(Envelope envelope, String newKeyReference, Map<String, String> aad) {
        byte[] plaintext = decrypt(envelope, aad);
        try {
            return encrypt(newKeyReference, plaintext, aad);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private void requireFresh(Instant expiry) {
        Instant now = clock.instant();
        if (!expiry.isAfter(now) || expiry.isAfter(now.plus(maximumPlaintextKeyLifetime))) {
            throw new SecurityException("KMS returned a stale or overlong plaintext data key");
        }
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) {
        if (key.length != KEY_BYTES) {
            throw new SecurityException("KMS data key must be 256 bits");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (AEADBadTagException exception) {
            throw new SecurityException("encrypted envelope authentication failed", exception);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("envelope encryption operation failed", exception);
        }
    }

    private static byte[] canonicalAad(Map<String, String> aad) {
        Objects.requireNonNull(aad, "aad");
        if (!aad.keySet().containsAll(java.util.Set.of("tenantId", "resourceId", "purpose"))) {
            throw new IllegalArgumentException("AAD requires tenantId, resourceId and purpose");
        }
        TreeMap<String, String> sorted = new TreeMap<>(aad);
        int size = sorted.entrySet().stream().mapToInt(entry -> 8
                + entry.getKey().getBytes(StandardCharsets.UTF_8).length
                + entry.getValue().getBytes(StandardCharsets.UTF_8).length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(size);
        sorted.forEach((key, value) -> {
            requireText(key, "AAD key");
            requireText(value, "AAD value");
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
            buffer.putInt(keyBytes.length).put(keyBytes).putInt(valueBytes.length).put(valueBytes);
        });
        return buffer.array();
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }
}
