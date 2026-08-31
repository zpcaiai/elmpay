package com.elmpay.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

/** KMS/HSM boundary for short-lived envelope data keys. */
public interface KmsClient {
    GeneratedDataKey generateDataKey(String keyReference, Map<String, String> encryptionContext,
            Duration maximumPlaintextLifetime);

    UnwrappedDataKey unwrapDataKey(String keyReference, String keyVersion, byte[] wrappedDataKey,
            Map<String, String> encryptionContext, Duration maximumPlaintextLifetime);

    final class GeneratedDataKey implements AutoCloseable {
        private final String keyReference;
        private final String keyVersion;
        private final Instant plaintextExpiresAt;
        private byte[] plaintextKey;
        private byte[] wrappedDataKey;
        private boolean closed;

        public GeneratedDataKey(String keyReference, String keyVersion, byte[] plaintextKey,
                byte[] wrappedDataKey, Instant plaintextExpiresAt) {
            this.keyReference = requireText(keyReference, "keyReference");
            this.keyVersion = requireText(keyVersion, "keyVersion");
            this.plaintextExpiresAt = Objects.requireNonNull(plaintextExpiresAt,
                    "plaintextExpiresAt");
            byte[] plaintextCopy = Objects.requireNonNull(
                    plaintextKey, "plaintextKey").clone();
            byte[] wrappedCopy = null;
            try {
                wrappedCopy = Objects.requireNonNull(
                        wrappedDataKey, "wrappedDataKey").clone();
                if (plaintextCopy.length != 32 || wrappedCopy.length < 32) {
                    throw new IllegalArgumentException("KMS data key material is invalid");
                }
                this.plaintextKey = plaintextCopy;
                this.wrappedDataKey = wrappedCopy;
            } catch (RuntimeException | Error exception) {
                Arrays.fill(plaintextCopy, (byte) 0);
                if (wrappedCopy != null) Arrays.fill(wrappedCopy, (byte) 0);
                throw exception;
            }
        }

        public synchronized String keyReference() { ensureOpen(); return keyReference; }
        public synchronized String keyVersion() { ensureOpen(); return keyVersion; }
        public synchronized byte[] plaintextKey() { ensureOpen(); return plaintextKey.clone(); }
        public synchronized byte[] wrappedDataKey() { ensureOpen(); return wrappedDataKey.clone(); }
        public synchronized Instant plaintextExpiresAt() {
            ensureOpen();
            return plaintextExpiresAt;
        }

        @Override public synchronized void close() {
            if (closed) return;
            closed = true;
            Arrays.fill(plaintextKey, (byte) 0);
            Arrays.fill(wrappedDataKey, (byte) 0);
            plaintextKey = new byte[0];
            wrappedDataKey = new byte[0];
        }

        @Override public String toString() { return "GeneratedDataKey[REDACTED]"; }

        private void ensureOpen() {
            if (closed) throw new IllegalStateException("generated KMS data key is closed");
        }
    }

    final class UnwrappedDataKey implements AutoCloseable {
        private final Instant plaintextExpiresAt;
        private byte[] plaintextKey;
        private boolean closed;

        public UnwrappedDataKey(byte[] plaintextKey, Instant plaintextExpiresAt) {
            this.plaintextExpiresAt = Objects.requireNonNull(plaintextExpiresAt,
                    "plaintextExpiresAt");
            this.plaintextKey = Objects.requireNonNull(plaintextKey, "plaintextKey").clone();
            if (this.plaintextKey.length != 32) {
                close();
                throw new IllegalArgumentException("unwrapped KMS data key is invalid");
            }
        }

        public synchronized byte[] plaintextKey() { ensureOpen(); return plaintextKey.clone(); }
        public synchronized Instant plaintextExpiresAt() {
            ensureOpen();
            return plaintextExpiresAt;
        }

        @Override public synchronized void close() {
            if (closed) return;
            closed = true;
            Arrays.fill(plaintextKey, (byte) 0);
            plaintextKey = new byte[0];
        }

        @Override public String toString() { return "UnwrappedDataKey[REDACTED]"; }

        private void ensureOpen() {
            if (closed) throw new IllegalStateException("unwrapped KMS data key is closed");
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
