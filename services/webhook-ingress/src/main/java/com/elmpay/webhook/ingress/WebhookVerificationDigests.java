package com.elmpay.webhook.ingress;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Objects;

/** Domain-separated immutable binding for a provider-verifier result. */
final class WebhookVerificationDigests {
    private static final byte[] DOMAIN = "elmpay:provider-webhook-verification:v1"
            .getBytes(StandardCharsets.US_ASCII);

    private WebhookVerificationDigests() {
    }

    static String sha256(byte[] value) {
        Objects.requireNonNull(value, "value");
        return HexFormat.of().formatHex(digest().digest(value));
    }

    static String verificationDigest(WebhookIngressService.Context context,
            WebhookIngressService.VerifiedEvent event, String rawBodySha256,
            String canonicalPayloadSha256) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(event, "event");
        requireDigest(rawBodySha256, "rawBodySha256");
        requireDigest(canonicalPayloadSha256, "canonicalPayloadSha256");
        MessageDigest digest = digest();
        field(digest, DOMAIN);
        field(digest, context.tenantId());
        field(digest, context.projectId());
        field(digest, context.provider());
        field(digest, context.merchantAccountId());
        field(digest, event.providerEventId());
        field(digest, event.eventType());
        field(digest, event.providerPaymentId());
        field(digest, event.businessOrderNo());
        field(digest, instant(event.occurredAt()));
        field(digest, instant(context.receivedAt()));
        field(digest, event.signatureKeyId());
        nullableField(digest, event.amountMinor() == null ? null
                : Long.toString(event.amountMinor()));
        nullableField(digest, event.currency());
        field(digest, event.canonicalSchema());
        field(digest, rawBodySha256);
        field(digest, canonicalPayloadSha256);
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String instant(Instant value) {
        // PostgreSQL TIMESTAMPTZ has microsecond resolution. Bind the digest to exactly the value
        // that can be persisted so a later transaction can recompute it byte-for-byte.
        return Objects.requireNonNull(value, "instant").truncatedTo(ChronoUnit.MICROS).toString();
    }

    private static void field(MessageDigest digest, String value) {
        field(digest, Objects.requireNonNull(value, "digest field")
                .getBytes(StandardCharsets.UTF_8));
    }

    private static void field(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    private static void nullableField(MessageDigest digest, String value) {
        if (value == null) {
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(-1).array());
        } else {
            field(digest, value);
        }
    }

    private static void requireDigest(String value, String name) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static MessageDigest digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
