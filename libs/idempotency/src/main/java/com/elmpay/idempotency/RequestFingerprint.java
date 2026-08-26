package com.elmpay.idempotency;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

public final class RequestFingerprint {
    private RequestFingerprint() {
    }

    public static String sha256(String canonicalPayload) {
        Objects.requireNonNull(canonicalPayload, "canonicalPayload");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonicalPayload.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK is missing SHA-256", exception);
        }
    }

    public static void validateKey(String key) {
        if (key == null || key.length() < 16 || key.length() > 128
                || !key.matches("[A-Za-z0-9._:-]+")) {
            throw new IdempotencyException("IDEMPOTENCY_KEY_INVALID",
                    "idempotency key must be 16-128 safe ASCII characters");
        }
    }
}
