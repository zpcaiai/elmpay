package com.elmpay.payment;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/** A provider callback after cryptographic verification and versioned semantic mapping. */
public record VerifiedProviderEffectCommand(
        String schemaVersion,
        String mappingVersion,
        UUID tenantId,
        UUID projectId,
        UUID providerAccountId,
        String provider,
        String providerEventId,
        String providerEventType,
        EffectKind effectKind,
        String providerPaymentId,
        String businessOrderNo,
        Long amountMinor,
        String currency,
        Instant providerOccurredAt,
        Instant verifiedAt,
        String verificationDigest,
        String canonicalPayloadSha256,
        String traceId) {

    public static final String SCHEMA_V1 = "verified-provider-effect.v1";
    public static final String MAPPING_V1 = "provider-event-map.v1";

    public enum EffectKind {
        PAYMENT_PENDING,
        PAYMENT_AUTHORIZED,
        PAYMENT_CAPTURED,
        PAYMENT_FAILED,
        PAYMENT_CANCELED,
        REFUND_PENDING,
        REFUND_SUCCEEDED,
        REFUND_FAILED,
        REFUND_CANCELED;

        public boolean refund() {
            return name().startsWith("REFUND_");
        }

        public boolean requiresMoney() {
            return this == PAYMENT_AUTHORIZED || this == PAYMENT_CAPTURED
                    || this == REFUND_PENDING || this == REFUND_SUCCEEDED
                    || this == REFUND_FAILED || this == REFUND_CANCELED;
        }
    }

    public VerifiedProviderEffectCommand {
        if (!SCHEMA_V1.equals(schemaVersion)) {
            throw new IllegalArgumentException("verified provider effect schema is unsupported");
        }
        if (!MAPPING_V1.equals(mappingVersion)) {
            throw new IllegalArgumentException("provider event mapping version is unsupported");
        }
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        provider = provider(provider);
        requireText(providerEventId, "providerEventId", 160);
        requireText(providerEventType, "providerEventType", 160);
        Objects.requireNonNull(effectKind, "effectKind");
        requireText(providerPaymentId, "providerPaymentId", 160);
        requireText(businessOrderNo, "businessOrderNo", 160);
        Objects.requireNonNull(providerOccurredAt, "providerOccurredAt");
        Objects.requireNonNull(verifiedAt, "verifiedAt");
        if (providerOccurredAt.isAfter(verifiedAt.plusSeconds(300))) {
            throw new IllegalArgumentException("providerOccurredAt is implausibly in the future");
        }
        if ((amountMinor == null) != (currency == null)) {
            throw new IllegalArgumentException("amountMinor and currency must be supplied together");
        }
        if (amountMinor != null && amountMinor <= 0) {
            throw new IllegalArgumentException("amountMinor must be positive");
        }
        if (effectKind.requiresMoney() && amountMinor == null) {
            throw new IllegalArgumentException("mapped provider effect requires exact money facts");
        }
        if (currency != null) {
            currency = currency.toUpperCase(Locale.ROOT);
            if (!currency.matches("[A-Z]{3}")) {
                throw new IllegalArgumentException("currency has an invalid format");
            }
        }
        requireDigest(verificationDigest, "verificationDigest");
        requireDigest(canonicalPayloadSha256, "canonicalPayloadSha256");
        requireText(traceId, "traceId", 128);
    }

    private static String provider(String value) {
        String normalized = Objects.requireNonNull(value, "provider").toLowerCase(Locale.ROOT);
        if (!normalized.matches("(?:wechat|alipay|stripe|paypal)")) {
            throw new IllegalArgumentException("provider is not callback-capable");
        }
        return normalized;
    }

    private static void requireText(String value, String field, int maximum) {
        if (value == null || value.isBlank() || value.length() > maximum
                || value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static void requireDigest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }
}
