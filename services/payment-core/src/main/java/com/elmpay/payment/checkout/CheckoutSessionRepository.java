package com.elmpay.payment.checkout;

import com.elmpay.idempotency.RequestFingerprint;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Durable checkout-session port. Raw browser bearer tokens are never persisted. */
public interface CheckoutSessionRepository {
    record Record(String sessionId, UUID tenantId, UUID projectId, UUID merchantId,
            UUID paymentIntentId, String businessOrderNo, long amountMinor, String currency,
            String returnRouteId, URI returnUri, String deviceContextDigest, Instant expiresAt,
            String keyId, String nonce, Set<String> allowedMethods, String createIdempotencyKey,
            String requestDigest, Instant createdAt) {
        public Record {
            if (!UUID.fromString(Objects.requireNonNull(sessionId, "sessionId")).toString()
                    .equals(sessionId)) {
                throw new IllegalArgumentException("checkout session id must be canonical UUID");
            }
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            Objects.requireNonNull(paymentIntentId, "paymentIntentId");
            if (businessOrderNo == null || businessOrderNo.isBlank()
                    || businessOrderNo.length() > 128 || amountMinor <= 0
                    || currency == null || !currency.matches("[A-Z]{3}")
                    || returnRouteId == null
                    || !returnRouteId.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
                throw new IllegalArgumentException("invalid immutable checkout snapshot");
            }
            returnUri = normalizeReturnUri(returnUri);
            if (deviceContextDigest == null || deviceContextDigest.isBlank()
                    || deviceContextDigest.length() > 128
                    || expiresAt == null || createdAt == null || !expiresAt.isAfter(createdAt)
                    || keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,64}")
                    || nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}")
                    || requestDigest == null || !requestDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid signed checkout claims");
            }
            RequestFingerprint.validateKey(createIdempotencyKey);
            if (allowedMethods == null || allowedMethods.isEmpty()) {
                throw new IllegalArgumentException("checkout methods are required");
            }
            allowedMethods = allowedMethods.stream().map(method -> {
                String normalized = Objects.requireNonNull(method, "allowed method")
                        .toLowerCase(Locale.ROOT);
                if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
                    throw new IllegalArgumentException("invalid checkout method");
                }
                return normalized;
            }).collect(Collectors.toUnmodifiableSet());
        }

        private static URI normalizeReturnUri(URI value) {
            Objects.requireNonNull(value, "returnUri");
            if (!value.isAbsolute() || value.getHost() == null || value.getUserInfo() != null
                    || value.getFragment() != null
                    || !"https".equalsIgnoreCase(value.getScheme())) {
                throw new IllegalArgumentException("checkout return URI must be absolute HTTPS");
            }
            String path = value.getRawPath() == null || value.getRawPath().isEmpty()
                    ? "/" : value.getRawPath();
            try {
                return new URI("https", null, value.getHost().toLowerCase(Locale.ROOT),
                        value.getPort(), path, value.getRawQuery(), null).normalize();
            } catch (URISyntaxException invalid) {
                throw new IllegalArgumentException("invalid checkout return URI", invalid);
            }
        }
    }

    Optional<Record> find(UUID tenantId, String sessionId);

    Optional<Record> findByCreateKey(UUID tenantId, UUID projectId, String idempotencyKey);

    /**
     * Inserts the candidate or returns the concurrent winner for the same create key.
     * Implementations must enforce tenant/project/key and payment-intent uniqueness.
     */
    Record createOrGet(Record candidate);
}
