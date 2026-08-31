package com.elmpay.payment.provider;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Short-lived provider secret lease whose internal buffers are wiped on close.
 *
 * <p>{@link #require(String)} returns a defensive copy; callers must wipe that copy. Prefer
 * {@link #use(String, SecretOperation)} when possible because it wipes the temporary copy even
 * when the operation fails. This type deliberately never renders material from {@code toString()}.
 */
public final class SecretMaterialProviderCredential implements ProviderCredential {
    @FunctionalInterface
    public interface SecretOperation<T> {
        T apply(byte[] secret);
    }

    private final String version;
    private final String leaseId;
    private final Instant expiresAt;
    private final Map<String, byte[]> material;
    private final Runnable revoker;
    private final AtomicBoolean closed = new AtomicBoolean();

    SecretMaterialProviderCredential(String version, String leaseId, Instant expiresAt,
            Map<String, byte[]> material, Runnable revoker) {
        this.version = requireText(version, "version");
        this.leaseId = requireText(leaseId, "leaseId");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        this.revoker = Objects.requireNonNull(revoker, "revoker");
        Objects.requireNonNull(material, "material");
        if (material.isEmpty() || material.size() > 64) {
            throw new IllegalArgumentException("credential material must contain 1..64 fields");
        }
        Map<String, byte[]> copy = new LinkedHashMap<>();
        long total = 0;
        try {
            for (Map.Entry<String, byte[]> entry : material.entrySet()) {
                String field = requireField(entry.getKey());
                byte[] secret = null;
                try {
                    secret = Objects.requireNonNull(entry.getValue(), "secret").clone();
                    if (secret.length == 0 || secret.length > 65_536) {
                        throw new IllegalArgumentException(
                                "credential field has an invalid size");
                    }
                    total += secret.length;
                    if (total > 262_144 || copy.putIfAbsent(field, secret) != null) {
                        throw new IllegalArgumentException("credential material is invalid");
                    }
                    secret = null;
                } finally {
                    if (secret != null) {
                        Arrays.fill(secret, (byte) 0);
                    }
                }
            }
        } catch (RuntimeException | Error exception) {
            wipe(copy);
            throw exception;
        }
        this.material = copy;
    }

    @Override
    public synchronized String version() {
        ensureOpen();
        return version;
    }

    public synchronized String leaseId() {
        ensureOpen();
        return leaseId;
    }

    public synchronized Instant expiresAt() {
        ensureOpen();
        return expiresAt;
    }

    public synchronized byte[] require(String field) {
        ensureOpen();
        byte[] value = material.get(requireField(field));
        if (value == null) {
            throw new IllegalArgumentException("credential field is unavailable");
        }
        return value.clone();
    }

    public synchronized <T> T use(String field, SecretOperation<T> operation) {
        Objects.requireNonNull(operation, "operation");
        byte[] copy = require(field);
        try {
            return operation.apply(copy);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    @Override
    public synchronized void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        RuntimeException failure = null;
        try {
            revoker.run();
        } catch (RuntimeException exception) {
            failure = exception;
        } finally {
            wipe(material);
            material.clear();
        }
        if (failure != null) {
            throw failure;
        }
    }

    @Override
    public String toString() {
        return "SecretMaterialProviderCredential[REDACTED]";
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("provider credential lease is closed");
        }
    }

    private static String requireField(String value) {
        if (value == null || !value.matches("[a-z][a-z0-9_.-]{0,63}")) {
            throw new IllegalArgumentException("credential field has an invalid format");
        }
        return value;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 256
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
        return value;
    }

    private static void wipe(Map<String, byte[]> values) {
        values.values().forEach(value -> Arrays.fill(value, (byte) 0));
    }
}
