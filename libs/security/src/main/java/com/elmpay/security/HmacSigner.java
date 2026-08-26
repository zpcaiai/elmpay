package com.elmpay.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/** JCA-backed HMAC signer for platform-owned session and business webhook signatures. */
public final class HmacSigner {
    private static final String ALGORITHM = "HmacSHA256";

    private final String keyId;
    private final SecretKey key;

    public HmacSigner(String keyId, SecretKey key) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.key = Objects.requireNonNull(key, "key");
        if (keyId.isBlank()) {
            throw new IllegalArgumentException("key id is required");
        }
    }

    public String keyId() {
        return keyId;
    }

    public String sign(byte[] payload) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(payload));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC operation failed", exception);
        }
    }

    public String sign(String payload) {
        return sign(payload.getBytes(StandardCharsets.UTF_8));
    }

    public boolean verify(byte[] payload, String signature) {
        try {
            byte[] supplied = Base64.getUrlDecoder().decode(signature);
            byte[] expected = Base64.getUrlDecoder().decode(sign(payload));
            return MessageDigest.isEqual(expected, supplied);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
