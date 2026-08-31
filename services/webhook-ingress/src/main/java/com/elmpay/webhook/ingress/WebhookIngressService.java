package com.elmpay.webhook.ingress;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Pattern;

/** Verifies a provider callback before opening a database connection or acknowledging it. */
public final class WebhookIngressService {
    public static final String CANONICAL_SCHEMA_V1 = "provider-webhook-effect.v1";
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Pattern CONTEXT_ID = Pattern.compile("[A-Za-z0-9_-]{3,64}");
    private static final Pattern PROVIDER = Pattern.compile("[a-z][a-z0-9-]{1,31}");

    public enum Outcome { ACCEPTED, DUPLICATE }

    public record Context(String tenantId, String projectId, String provider,
            String merchantAccountId, Instant receivedAt) {
        public Context {
            requireContextId(tenantId, "tenantId");
            requireContextId(projectId, "projectId");
            if (provider == null || !PROVIDER.matcher(provider).matches()) {
                throw new IllegalArgumentException("provider has an invalid format");
            }
            requireContextId(merchantAccountId, "merchantAccountId");
            Objects.requireNonNull(receivedAt, "receivedAt");
        }
    }

    public record VerifiedEvent(String providerEventId, String eventType, String providerPaymentId,
            String businessOrderNo, Instant occurredAt, String signatureKeyId,
            Long amountMinor, String currency, String canonicalSchema, byte[] canonicalPayload) {
        public VerifiedEvent(String providerEventId, String eventType, String providerPaymentId,
                String businessOrderNo, Instant occurredAt, String signatureKeyId,
                byte[] canonicalPayload) {
            this(providerEventId, eventType, providerPaymentId, businessOrderNo, occurredAt,
                    signatureKeyId, null, null, CANONICAL_SCHEMA_V1, canonicalPayload);
        }

        public VerifiedEvent {
            requireBounded(providerEventId, "providerEventId", 1, 160);
            requireBounded(eventType, "eventType", 1, 160);
            requireBounded(providerPaymentId, "providerPaymentId", 1, 160);
            requireBounded(businessOrderNo, "businessOrderNo", 1, 160);
            Objects.requireNonNull(occurredAt, "occurredAt");
            requireBounded(signatureKeyId, "signatureKeyId", 1, 160);
            if ((amountMinor == null) != (currency == null)) {
                throw new IllegalArgumentException("amountMinor and currency must be supplied together");
            }
            if (currency != null && !currency.matches("[A-Z]{3}")) {
                throw new IllegalArgumentException("currency has an invalid format");
            }
            if (!CANONICAL_SCHEMA_V1.equals(canonicalSchema)) {
                throw new IllegalArgumentException("canonicalSchema is unsupported");
            }
            canonicalPayload = Objects.requireNonNull(canonicalPayload, "canonicalPayload").clone();
            if (canonicalPayload.length == 0 || canonicalPayload.length > 32_768) {
                throw new IllegalArgumentException("canonicalPayload has an invalid size");
            }
        }

        @Override
        public byte[] canonicalPayload() {
            return canonicalPayload.clone();
        }
    }

    public record Receipt(Outcome outcome, String providerEventId, String rawBodySha256) {
        public Receipt {
            Objects.requireNonNull(outcome, "outcome");
            requireBounded(providerEventId, "providerEventId", 1, 160);
            if (rawBodySha256 == null || !rawBodySha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("rawBodySha256 has an invalid format");
            }
        }
    }

    @FunctionalInterface
    public interface ProviderWebhookVerifier {
        VerifiedEvent verify(Context context, Map<String, String> headers,
                byte[] rawBody, Instant receivedAt);
    }

    @FunctionalInterface
    public interface Inbox {
        /** @return true if inserted; false only when the provider event already exists. */
        boolean store(Context context, VerifiedEvent event, String rawBodySha256);
    }

    private final Map<String, ProviderWebhookVerifier> verifiers;
    private final Inbox inbox;

    public WebhookIngressService(Map<String, ProviderWebhookVerifier> verifiers, Inbox inbox) {
        this.verifiers = Map.copyOf(verifiers);
        if (this.verifiers.isEmpty()) {
            throw new IllegalArgumentException("at least one provider verifier is required");
        }
        this.inbox = Objects.requireNonNull(inbox, "inbox");
    }

    public Receipt ingest(Context context, Map<String, String> headers, byte[] rawBody) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(rawBody, "rawBody");
        if (rawBody.length == 0 || rawBody.length > MAX_BODY_BYTES) {
            throw new SecurityException("provider webhook body size is invalid");
        }
        rejectObviouslySensitiveCardFields(rawBody);
        ProviderWebhookVerifier verifier = verifiers.get(context.provider());
        if (verifier == null) {
            throw new SecurityException("unsupported provider");
        }

        // This call must complete successfully before any durable write occurs. The bounded clone
        // is erased after verification and is never handed to the durable inbox.
        byte[] verificationBody = rawBody.clone();
        VerifiedEvent verified;
        try {
            verified = verifier.verify(context, Map.copyOf(headers), verificationBody,
                    context.receivedAt());
        } finally {
            Arrays.fill(verificationBody, (byte) 0);
        }
        String digest = sha256(rawBody);
        boolean inserted = inbox.store(context, verified, digest);
        return new Receipt(inserted ? Outcome.ACCEPTED : Outcome.DUPLICATE,
                verified.providerEventId(), digest);
    }

    private static void rejectObviouslySensitiveCardFields(byte[] rawBody) {
        for (String field : new String[] {"\"card_number\"", "\"cardnumber\"", "\"pan\"",
                "\"cvv\"", "\"cvc\"", "\"track1\"", "\"track2\""}) {
            if (containsAsciiIgnoreCase(rawBody, field)) {
                throw new SecurityException("raw card data is forbidden");
            }
        }
    }

    private static boolean containsAsciiIgnoreCase(byte[] value, String needle) {
        for (int start = 0; start <= value.length - needle.length(); start++) {
            boolean match = true;
            for (int offset = 0; offset < needle.length(); offset++) {
                int actual = value[start + offset] & 0xff;
                int expected = needle.charAt(offset);
                if (actual >= 'A' && actual <= 'Z') {
                    actual += 'a' - 'A';
                }
                if (expected >= 'A' && expected <= 'Z') {
                    expected += 'a' - 'A';
                }
                if (actual != expected) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void requireContextId(String value, String name) {
        if (value == null || !CONTEXT_ID.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireBounded(String value, String name, int minimum, int maximum) {
        if (value == null || value.length() < minimum || value.length() > maximum
                || value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }
}
