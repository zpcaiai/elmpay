package com.elmpay.payment.checkout;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Canonical HMAC checkout bearer; the token is derived and never stored. */
public final class CheckoutTokenSigner {
    private final Map<String, byte[]> keys;
    private final String activeKeyId;
    private final SecureRandom random = new SecureRandom();

    public CheckoutTokenSigner(Map<String, byte[]> keys, String activeKeyId) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("at least one checkout signing key is required");
        }
        Map<String, byte[]> copy = new LinkedHashMap<>();
        keys.forEach((id, secret) -> {
            if (id == null || !id.matches("[A-Za-z0-9._-]{1,64}")
                    || secret == null || secret.length < 32) {
                throw new IllegalArgumentException("invalid checkout signing key");
            }
            copy.put(id, secret.clone());
        });
        if (!copy.containsKey(activeKeyId)) {
            throw new IllegalArgumentException("active checkout signing key is absent");
        }
        this.keys = Map.copyOf(copy);
        this.activeKeyId = activeKeyId;
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    public String newNonce() {
        byte[] value = new byte[32];
        random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public String token(CheckoutSessionRepository.Record record) {
        String tenantClaim = Base64.getUrlEncoder().withoutPadding().encodeToString(
                record.tenantId().toString().getBytes(StandardCharsets.US_ASCII));
        return tenantClaim + "." + signature(record);
    }

    public java.util.UUID tenantClaim(String token) {
        try {
            String[] parts = Objects.requireNonNullElse(token, "").split("\\.", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("invalid checkout token");
            }
            String decoded = new String(Base64.getUrlDecoder().decode(parts[0]),
                    StandardCharsets.US_ASCII);
            return java.util.UUID.fromString(decoded);
        } catch (IllegalArgumentException invalid) {
            throw new SecurityException("invalid checkout token", invalid);
        }
    }

    public boolean verify(CheckoutSessionRepository.Record record, String suppliedToken) {
        String expected = token(record);
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                Objects.requireNonNullElse(suppliedToken, "").getBytes(StandardCharsets.US_ASCII));
    }

    private String signature(CheckoutSessionRepository.Record record) {
        byte[] key = keys.get(record.keyId());
        if (key == null) {
            throw new SecurityException("checkout signing key version is unavailable");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    mac.doFinal(canonical(record)));
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("HmacSHA256 is unavailable", unavailable);
        }
    }

    private static byte[] canonical(CheckoutSessionRepository.Record record) {
        List<String> methods = record.allowedMethods().stream().sorted(Comparator.naturalOrder())
                .toList();
        List<byte[]> values = new ArrayList<>();
        add(values, "checkout-session-v2");
        add(values, record.sessionId());
        add(values, record.tenantId().toString());
        add(values, record.projectId().toString());
        add(values, record.merchantId().toString());
        add(values, record.paymentIntentId().toString());
        add(values, record.businessOrderNo());
        add(values, Long.toString(record.amountMinor()));
        add(values, record.currency());
        add(values, record.returnRouteId());
        add(values, record.returnUri().toASCIIString());
        add(values, record.deviceContextDigest());
        add(values, Long.toString(record.expiresAt().toEpochMilli()));
        add(values, record.keyId());
        add(values, record.nonce());
        methods.forEach(method -> add(values, method));
        int size = values.stream().mapToInt(value -> Integer.BYTES + value.length).sum();
        ByteBuffer result = ByteBuffer.allocate(size);
        values.forEach(value -> result.putInt(value.length).put(value));
        return result.array();
    }

    private static void add(List<byte[]> values, String value) {
        values.add(value.getBytes(StandardCharsets.UTF_8));
    }
}
