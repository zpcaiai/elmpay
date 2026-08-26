package com.elmpay.payment.checkout;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Creates opaque, signed and exactly-once redeemable checkout links/QR payloads. */
public final class PaymentLinkService {
    public record Link(String token, String sessionId, String tenantId, Instant expiresAt) {}
    private record Stored(String tenantId, String sessionId, Instant expiresAt, AtomicBoolean consumed) {}

    private final byte[] key;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Stored> links = new ConcurrentHashMap<>();

    public PaymentLinkService(byte[] key, Clock clock) {
        if (key == null || key.length < 32) throw new IllegalArgumentException("HMAC key must be >= 256 bits");
        this.key = key.clone();
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Link create(String tenantId, String sessionId, Duration ttl) {
        require(tenantId, "tenantId");
        require(sessionId, "sessionId");
        if (ttl == null || ttl.isZero() || ttl.isNegative() || ttl.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException("link ttl must be between 1ns and 15 minutes");
        }
        Instant expires = clock.instant().plus(ttl);
        byte[] nonce = new byte[24];
        random.nextBytes(nonce);
        String id = UUID.randomUUID().toString();
        String payload = encode(id) + "." + encode(tenantId) + "." + encode(sessionId) + "."
                + expires.toEpochMilli() + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
        String token = payload + "." + hmac(payload);
        links.put(tokenDigest(token), new Stored(tenantId, sessionId, expires, new AtomicBoolean(false)));
        return new Link(token, sessionId, tenantId, expires);
    }

    public String redeem(String tenantId, String token) {
        require(tenantId, "tenantId");
        if (!validSignature(token)) throw new SecurityException("invalid payment link signature");
        Stored stored = links.get(tokenDigest(token));
        if (stored == null || !MessageDigest.isEqual(bytes(stored.tenantId()), bytes(tenantId))) {
            throw new SecurityException("unknown payment link");
        }
        if (!clock.instant().isBefore(stored.expiresAt())) throw new SecurityException("payment link expired");
        if (!stored.consumed().compareAndSet(false, true)) throw new SecurityException("payment link already consumed");
        return stored.sessionId();
    }

    /** QR encoders should encode this same-origin path, never an arbitrary return URL. */
    public String qrPayload(Link link) { return "/checkout/link/" + link.token(); }

    private boolean validSignature(String token) {
        if (token == null) return false;
        int separator = token.lastIndexOf('.');
        if (separator < 0) return false;
        String payload = token.substring(0, separator);
        try {
            return MessageDigest.isEqual(Base64.getUrlDecoder().decode(hmac(payload)),
                    Base64.getUrlDecoder().decode(token.substring(separator + 1)));
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private String hmac(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(bytes(value)));
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }

    private static String tokenDigest(String token) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(bytes(token)));
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(value));
    }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static void require(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
    }
}
