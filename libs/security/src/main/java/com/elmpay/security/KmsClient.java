package com.elmpay.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/** KMS/HSM boundary for short-lived envelope data keys. */
public interface KmsClient {
    GeneratedDataKey generateDataKey(String keyReference, Map<String, String> encryptionContext,
            Duration maximumPlaintextLifetime);

    UnwrappedDataKey unwrapDataKey(String keyReference, String keyVersion, byte[] wrappedDataKey,
            Map<String, String> encryptionContext, Duration maximumPlaintextLifetime);

    record GeneratedDataKey(String keyReference, String keyVersion, byte[] plaintextKey,
            byte[] wrappedDataKey, Instant plaintextExpiresAt) {
        public GeneratedDataKey {
            requireText(keyReference, "keyReference");
            requireText(keyVersion, "keyVersion");
            plaintextKey = plaintextKey.clone();
            wrappedDataKey = wrappedDataKey.clone();
            if (plaintextKey.length != 32 || wrappedDataKey.length < 32) {
                throw new IllegalArgumentException("KMS data key material is invalid");
            }
            if (plaintextExpiresAt == null) {
                throw new IllegalArgumentException("KMS plaintext key expiry is required");
            }
        }

        @Override public byte[] plaintextKey() { return plaintextKey.clone(); }
        @Override public byte[] wrappedDataKey() { return wrappedDataKey.clone(); }
    }

    record UnwrappedDataKey(byte[] plaintextKey, Instant plaintextExpiresAt) {
        public UnwrappedDataKey {
            plaintextKey = plaintextKey.clone();
            if (plaintextKey.length != 32 || plaintextExpiresAt == null) {
                throw new IllegalArgumentException("unwrapped KMS data key is invalid");
            }
        }

        @Override public byte[] plaintextKey() { return plaintextKey.clone(); }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }
}
