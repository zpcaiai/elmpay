package com.elmpay.webhook.ingress;

import java.sql.Connection;
import java.time.Instant;
import java.util.Objects;

/**
 * Internally trusted boundary for applying a verified provider webhook to payment/commerce state.
 *
 * <p>The implementation must use the supplied transaction for every business write and external
 * effect outbox record. It must not perform a direct network call. The verifier metadata proves
 * only that this service verified a provider callback; it is not a provider-official Ed25519
 * receipt and must never be represented as one.
 */
@FunctionalInterface
public interface WebhookEffectPort {
    void apply(Connection transaction, Effect effect) throws Exception;

    /** Safe classification crossing the internal dispatcher boundary; messages are never logged. */
    final class EffectFailure extends Exception {
        private static final long serialVersionUID = 1L;
        private final String failureCode;
        private final boolean permanent;

        public EffectFailure(String failureCode, boolean permanent, Throwable cause) {
            super("verified provider effect was rejected", cause);
            if (failureCode == null || !failureCode.matches("[A-Z][A-Z0-9_]{2,79}")) {
                throw new IllegalArgumentException("failureCode has an invalid format");
            }
            this.failureCode = failureCode;
            this.permanent = permanent;
        }

        public String failureCode() {
            return failureCode;
        }

        public boolean permanent() {
            return permanent;
        }
    }

    /** Immutable, digest-bound facts emitted by the provider webhook verifier. */
    record Effect(long inboxId, String tenantId, String projectId, String provider,
            String merchantAccountId, String providerEventId, String eventType,
            String providerPaymentId, String businessOrderNo, Instant occurredAt,
            Instant receivedAt, String signatureKeyId, Long amountMinor, String currency,
            String canonicalSchema, String rawBodySha256,
            String canonicalPayloadSha256, String verificationDigest, byte[] canonicalPayload,
            int processingAttempt, long fencingToken) {
        public Effect {
            if (inboxId <= 0) {
                throw new IllegalArgumentException("inboxId must be positive");
            }
            requireText(tenantId, "tenantId");
            requireText(projectId, "projectId");
            requireText(provider, "provider");
            requireText(merchantAccountId, "merchantAccountId");
            requireText(providerEventId, "providerEventId");
            requireText(eventType, "eventType");
            requireText(providerPaymentId, "providerPaymentId");
            requireText(businessOrderNo, "businessOrderNo");
            Objects.requireNonNull(occurredAt, "occurredAt");
            Objects.requireNonNull(receivedAt, "receivedAt");
            requireText(signatureKeyId, "signatureKeyId");
            if ((amountMinor == null) != (currency == null)) {
                throw new IllegalArgumentException("amountMinor and currency must be supplied together");
            }
            if (currency != null && !currency.matches("[A-Z]{3}")) {
                throw new IllegalArgumentException("currency has an invalid format");
            }
            if (!WebhookIngressService.CANONICAL_SCHEMA_V1.equals(canonicalSchema)) {
                throw new IllegalArgumentException("canonicalSchema is unsupported");
            }
            requireDigest(rawBodySha256, "rawBodySha256");
            requireDigest(canonicalPayloadSha256, "canonicalPayloadSha256");
            requireDigest(verificationDigest, "verificationDigest");
            canonicalPayload = Objects.requireNonNull(canonicalPayload, "canonicalPayload").clone();
            if (canonicalPayload.length == 0 || canonicalPayload.length > 32_768) {
                throw new IllegalArgumentException("canonicalPayload has an invalid size");
            }
            if (processingAttempt <= 0) {
                throw new IllegalArgumentException("processingAttempt must be positive");
            }
            if (fencingToken <= 0) {
                throw new IllegalArgumentException("fencingToken must be positive");
            }
        }

        @Override
        public byte[] canonicalPayload() {
            return canonicalPayload.clone();
        }

        private static void requireText(String value, String name) {
            if (value == null || value.isBlank() || value.length() > 160
                    || value.chars().anyMatch(character -> character < 0x20)) {
                throw new IllegalArgumentException(name + " has an invalid format");
            }
        }

        private static void requireDigest(String value, String name) {
            if (value == null || !value.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException(name + " has an invalid format");
            }
        }
    }
}
