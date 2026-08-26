package com.elmpay.webhook.ingress;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Verifies a provider callback before opening a database connection or acknowledging it. */
public final class WebhookIngressService {
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
            byte[] canonicalPayload) {
        public VerifiedEvent {
            requireBounded(providerEventId, "providerEventId", 1, 160);
            requireBounded(eventType, "eventType", 1, 160);
            requireBounded(providerPaymentId, "providerPaymentId", 1, 160);
            requireBounded(businessOrderNo, "businessOrderNo", 1, 160);
            Objects.requireNonNull(occurredAt, "occurredAt");
            requireBounded(signatureKeyId, "signatureKeyId", 1, 160);
            canonicalPayload = Objects.requireNonNull(canonicalPayload, "canonicalPayload").clone();
            if (canonicalPayload.length == 0 || canonicalPayload.length > MAX_BODY_BYTES) {
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
        VerifiedEvent verify(String merchantAccountId, Map<String, String> headers,
                byte[] rawBody, Instant receivedAt);
    }

    @FunctionalInterface
    public interface Inbox {
        /** @return true if inserted; false only when the provider event already exists. */
        boolean store(Context context, VerifiedEvent event, byte[] rawBody, String rawBodySha256);
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

        // This call must complete successfully before any durable write occurs.
        VerifiedEvent verified = verifier.verify(context.merchantAccountId(), Map.copyOf(headers),
                rawBody.clone(), context.receivedAt());
        String digest = sha256(rawBody);
        boolean inserted = inbox.store(context, verified, rawBody.clone(), digest);
        return new Receipt(inserted ? Outcome.ACCEPTED : Outcome.DUPLICATE,
                verified.providerEventId(), digest);
    }

    private static void rejectObviouslySensitiveCardFields(byte[] rawBody) {
        String body = new String(rawBody, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        for (String field : new String[] {"\"card_number\"", "\"cardnumber\"", "\"pan\"",
                "\"cvv\"", "\"cvc\"", "\"track1\"", "\"track2\""}) {
            if (body.contains(field)) {
                throw new SecurityException("raw card data is forbidden");
            }
        }
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
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }
}
