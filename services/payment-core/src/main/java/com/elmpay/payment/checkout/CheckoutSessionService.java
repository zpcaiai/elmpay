package com.elmpay.payment.checkout;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Server-authoritative checkout sessions.  The signed payload is canonical and
 * includes every field that could change who is paid, how much is paid, where
 * the browser returns, and how long the authorization is usable.
 */
public final class CheckoutSessionService {
    public enum Status { OPEN, CONSUMED, EXPIRED }

    public record CreateRequest(
            String tenantId,
            String projectId,
            String orderReference,
            long amountMinor,
            String currency,
            URI returnUri,
            String deviceContextDigest,
            Duration ttl) {
        public CreateRequest {
            requireId(tenantId, "tenantId");
            requireId(projectId, "projectId");
            requireId(orderReference, "orderReference");
            if (amountMinor <= 0) throw new IllegalArgumentException("amountMinor must be positive");
            currency = normalizeCurrency(currency);
            Objects.requireNonNull(returnUri, "returnUri");
            requireId(deviceContextDigest, "deviceContextDigest");
            Objects.requireNonNull(ttl, "ttl");
            if (ttl.isNegative() || ttl.isZero() || ttl.compareTo(Duration.ofMinutes(30)) > 0) {
                throw new IllegalArgumentException("ttl must be between 1ns and 30 minutes");
            }
        }
    }

    public record Session(
            String id,
            String tenantId,
            String projectId,
            String orderReference,
            long amountMinor,
            String currency,
            URI returnUri,
            String deviceContextDigest,
            Instant expiresAt,
            String keyId,
            String nonce,
            String signature,
            Status status) {}

    public record ConsumeResult(boolean consumed, Status status) {}

    private record Stored(Session immutable, AtomicReference<Status> status) {}

    private final Map<String, byte[]> keys;
    private final String activeKeyId;
    private final Set<URI> allowedReturnUris;
    private final Clock clock;
    private final SecureRandom random;
    private final ConcurrentHashMap<String, Stored> sessions = new ConcurrentHashMap<>();

    public CheckoutSessionService(
            Map<String, byte[]> keys,
            String activeKeyId,
            Collection<URI> allowedReturnUris,
            Clock clock) {
        if (keys == null || keys.isEmpty()) throw new IllegalArgumentException("at least one signing key is required");
        Map<String, byte[]> copy = new LinkedHashMap<>();
        keys.forEach((id, secret) -> {
            requireId(id, "key id");
            if (secret == null || secret.length < 32) throw new IllegalArgumentException("HMAC keys must be >= 256 bits");
            copy.put(id, secret.clone());
        });
        if (!copy.containsKey(activeKeyId)) throw new IllegalArgumentException("active key is absent");
        this.keys = Map.copyOf(copy);
        this.activeKeyId = activeKeyId;
        this.allowedReturnUris = Set.copyOf(Objects.requireNonNull(allowedReturnUris, "allowedReturnUris"));
        if (this.allowedReturnUris.isEmpty()) throw new IllegalArgumentException("return allowlist is empty");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = new SecureRandom();
    }

    public Session create(CreateRequest request) {
        Objects.requireNonNull(request, "request");
        if (!allowedReturnUris.contains(normalizedReturnUri(request.returnUri()))) {
            throw new SecurityException("return URI is not registered");
        }
        Instant expiresAt = clock.instant().plus(request.ttl());
        String id = UUID.randomUUID().toString();
        byte[] nonceBytes = new byte[32];
        random.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
        Session unsigned = new Session(id, request.tenantId(), request.projectId(), request.orderReference(),
                request.amountMinor(), request.currency(), normalizedReturnUri(request.returnUri()),
                request.deviceContextDigest(), expiresAt, activeKeyId, nonce, "", Status.OPEN);
        Session signed = withStatusAndSignature(unsigned, Status.OPEN, sign(unsigned));
        if (sessions.putIfAbsent(id, new Stored(signed, new AtomicReference<>(Status.OPEN))) != null) {
            throw new IllegalStateException("secure random session id collision");
        }
        return signed;
    }

    public Optional<Session> find(String tenantId, String sessionId) {
        Stored stored = sessions.get(sessionId);
        if (stored == null || !stored.immutable().tenantId().equals(tenantId)) return Optional.empty();
        expireIfNecessary(stored);
        return Optional.of(withStatusAndSignature(stored.immutable(), stored.status().get(), stored.immutable().signature()));
    }

    /** Exactly one caller can move an OPEN session to CONSUMED. */
    public ConsumeResult consume(String tenantId, String sessionId, String signature) {
        Stored stored = sessions.get(sessionId);
        if (stored == null || !stored.immutable().tenantId().equals(tenantId)) {
            throw new SecurityException("unknown checkout session");
        }
        if (!verify(stored.immutable(), signature)) throw new SecurityException("invalid checkout signature");
        expireIfNecessary(stored);
        boolean consumed = stored.status().compareAndSet(Status.OPEN, Status.CONSUMED);
        return new ConsumeResult(consumed, stored.status().get());
    }

    public boolean verify(Session session, String suppliedSignature) {
        byte[] expected = decodeSignature(sign(session));
        byte[] supplied;
        try {
            supplied = decodeSignature(suppliedSignature);
        } catch (IllegalArgumentException invalidEncoding) {
            supplied = new byte[0];
        }
        return MessageDigest.isEqual(expected, supplied);
    }

    private void expireIfNecessary(Stored stored) {
        if (!clock.instant().isBefore(stored.immutable().expiresAt())) {
            stored.status().compareAndSet(Status.OPEN, Status.EXPIRED);
        }
    }

    private String sign(Session session) {
        byte[] key = keys.get(session.keyId());
        if (key == null) throw new SecurityException("unknown signing key");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(canonical(session)));
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("HmacSHA256 unavailable", unavailable);
        }
    }

    private static byte[] canonical(Session session) {
        List<byte[]> values = new ArrayList<>();
        values.add(bytes("checkout-session-v1"));
        values.add(bytes(session.id()));
        values.add(bytes(session.tenantId()));
        values.add(bytes(session.projectId()));
        values.add(bytes(session.orderReference()));
        values.add(bytes(Long.toString(session.amountMinor())));
        values.add(bytes(session.currency()));
        values.add(bytes(session.returnUri().toASCIIString()));
        values.add(bytes(session.deviceContextDigest()));
        values.add(bytes(Long.toString(session.expiresAt().toEpochMilli())));
        values.add(bytes(session.keyId()));
        values.add(bytes(session.nonce()));
        int size = values.stream().mapToInt(value -> Integer.BYTES + value.length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(size);
        values.forEach(value -> buffer.putInt(value.length).put(value));
        return buffer.array();
    }

    private static Session withStatusAndSignature(Session value, Status status, String signature) {
        return new Session(value.id(), value.tenantId(), value.projectId(), value.orderReference(),
                value.amountMinor(), value.currency(), value.returnUri(), value.deviceContextDigest(),
                value.expiresAt(), value.keyId(), value.nonce(), signature, status);
    }

    private static URI normalizedReturnUri(URI uri) {
        if (!uri.isAbsolute() || uri.getHost() == null || !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new SecurityException("return URI must be an absolute HTTPS URI without user-info or fragment");
        }
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        try {
            return new URI("https", null, uri.getHost().toLowerCase(Locale.ROOT), uri.getPort(), path,
                    uri.getRawQuery(), null).normalize();
        } catch (java.net.URISyntaxException invalid) {
            throw new IllegalArgumentException("invalid return URI", invalid);
        }
    }

    private static String normalizeCurrency(String value) {
        if (value == null || !value.matches("[A-Za-z]{3}")) throw new IllegalArgumentException("invalid currency");
        return value.toUpperCase(Locale.ROOT);
    }

    private static void requireId(String value, String label) {
        if (value == null || value.isBlank() || value.length() > 200) {
            throw new IllegalArgumentException(label + " is required and must be <= 200 characters");
        }
    }

    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] decodeSignature(String value) {
        return Base64.getUrlDecoder().decode(Objects.requireNonNullElse(value, ""));
    }
}
