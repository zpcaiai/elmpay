package com.elmpay.webhook.ingress;

import com.elmpay.money.Money;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

/** Bridges production provider ports into the verify-before-write ingress contract. */
public final class ProviderWebhookVerifiers {
    private static final String CANONICAL_SCHEMA = WebhookIngressService.CANONICAL_SCHEMA_V1;
    private static final int MAX_PROVIDER_FACTS = 32;
    private static final int MAX_PROVIDER_FACT_VALUE = 512;
    private static final Set<String> REJECTED_FACT_NAMES = Set.of(
            "pan", "card_number", "cardnumber", "cvv", "cvc", "track1", "track2",
            "secret", "client_secret", "access_token", "authorization", "email", "phone",
            "address", "customer_name", "payer_name");
    private ProviderWebhookVerifiers() {
    }

    public static Map<String, WebhookIngressService.ProviderWebhookVerifier> create(
            List<ProviderAdapter> adapters) {
        Objects.requireNonNull(adapters, "adapters");
        Map<String, WebhookIngressService.ProviderWebhookVerifier> result = new LinkedHashMap<>();
        for (ProviderAdapter adapter : adapters) {
            Objects.requireNonNull(adapter, "provider adapter");
            String provider = Objects.requireNonNull(adapter.provider(), "provider");
            // Apple Pay payment tokens are completed by the selected PSP and do not own a
            // provider-callback endpoint. Endpoint providers use the same constrained grammar
            // as the durable registry migration.
            if (!provider.matches("[a-z][a-z0-9-]{1,31}")) {
                continue;
            }
            WebhookIngressService.ProviderWebhookVerifier verifier = (context, headers, rawBody,
                    receivedAt) -> verify(adapter, context, headers, rawBody, receivedAt);
            if (result.putIfAbsent(provider, verifier) != null) {
                throw new IllegalArgumentException("duplicate provider webhook verifier: " + provider);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("at least one callback-capable provider is required");
        }
        return Map.copyOf(result);
    }

    private static WebhookIngressService.VerifiedEvent verify(ProviderAdapter adapter,
            WebhookIngressService.Context context, Map<String, String> headers, byte[] rawBody,
            java.time.Instant receivedAt) {
        UUID tenantId = parseUuid(context.tenantId(), "tenantId");
        UUID merchantAccountId = parseUuid(context.merchantAccountId(), "merchantAccountId");
        VerifiedProviderEvent event;
        try (WebhookRequest request = new WebhookRequest(tenantId, merchantAccountId, headers,
                rawBody, receivedAt)) {
            event = Objects.requireNonNull(adapter.verifyWebhook(request),
                    "provider verified event");
        }
        if (!tenantId.equals(event.tenantId())
                || !merchantAccountId.equals(event.merchantAccountId())) {
            throw new SecurityException("provider webhook scope binding changed during verification");
        }
        Money amount = event.amount();
        return new WebhookIngressService.VerifiedEvent(event.providerEventId(), event.eventType(),
                event.providerPaymentId(), event.businessOrderNo(), event.providerOccurredAt(),
                event.signatureKeyId(), amount == null ? null : amount.amountMinor(),
                amount == null ? null : amount.currency().code(), CANONICAL_SCHEMA,
                canonicalPayload(adapter.provider(), event));
    }

    private static UUID parseUuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("provider webhook " + field + " is not a UUID", exception);
        }
    }

    private static byte[] canonicalPayload(String provider, VerifiedProviderEvent event) {
        validateProviderFacts(event.canonicalData());
        TreeMap<String, String> facts = new TreeMap<>();
        facts.put("schema", CANONICAL_SCHEMA);
        facts.put("provider", provider);
        facts.put("business_order_no", event.businessOrderNo());
        facts.put("event_type", event.eventType());
        facts.put("merchant_account_id", event.merchantAccountId().toString());
        facts.put("provider_event_id", event.providerEventId());
        facts.put("provider_payment_id", event.providerPaymentId());
        facts.put("provider_occurred_at", event.providerOccurredAt().toString());
        facts.put("signature_key_id", event.signatureKeyId());
        facts.put("tenant_id", event.tenantId().toString());
        Money amount = event.amount();
        if (amount != null) {
            facts.put("amount_minor", Long.toString(amount.amountMinor()));
            facts.put("currency", amount.currency().code());
            facts.put("currency_metadata_version", amount.currency().metadataVersion());
        }
        addAllowlistedProviderFacts(provider, event, facts);
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> fact : facts.entrySet()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            appendJsonString(json, fact.getKey());
            json.append(':');
            appendJsonString(json, fact.getValue());
        }
        byte[] payload = json.append('}').toString().getBytes(StandardCharsets.UTF_8);
        if (payload.length > 32_768) {
            throw new SecurityException("canonical provider webhook facts are too large");
        }
        return payload;
    }

    private static void addAllowlistedProviderFacts(String provider, VerifiedProviderEvent event,
            Map<String, String> target) {
        Map<String, String> source = event.canonicalData();
        // These fields have strict typed validation and are advisory audit facts only. Payment
        // state dispatch uses the explicit Effect fields, never arbitrary provider map keys.
        if ("stripe".equals(provider)) {
            String outOfOrder = source.get("out_of_order");
            if (outOfOrder != null) {
                if (!outOfOrder.equals("true") && !outOfOrder.equals("false")) {
                    throw new SecurityException("Stripe out_of_order is not boolean");
                }
                target.put("provider_out_of_order", outOfOrder);
            }
        }
        String tradeStatus = source.get("trade_status");
        if ("alipay".equals(provider) && event.eventType().startsWith("alipay.")
                && tradeStatus != null) {
            if (!tradeStatus.matches("[A-Z][A-Z0-9_]{1,31}")
                    || !event.eventType().equals("alipay."
                            + tradeStatus.toLowerCase(java.util.Locale.ROOT))) {
                throw new SecurityException("Alipay trade status is not bound to event type");
            }
            target.put("provider_status", tradeStatus);
        }
    }

    private static void validateProviderFacts(Map<String, String> facts) {
        if (facts.size() > MAX_PROVIDER_FACTS) {
            throw new SecurityException("provider webhook has too many canonical facts");
        }
        for (Map.Entry<String, String> fact : facts.entrySet()) {
            String key = Objects.requireNonNull(fact.getKey(), "canonical fact key");
            String value = Objects.requireNonNull(fact.getValue(), "canonical fact value");
            if (!key.matches("[a-z][a-z0-9_]{0,63}")) {
                throw new SecurityException("provider webhook fact name is invalid");
            }
            if (REJECTED_FACT_NAMES.stream().anyMatch(rejected -> key.equals(rejected)
                    || key.endsWith("_" + rejected))) {
                throw new SecurityException("sensitive provider webhook fact is forbidden");
            }
            if (value.length() > MAX_PROVIDER_FACT_VALUE
                    || value.codePoints().anyMatch(codePoint -> codePoint < 0x20 || codePoint == 0x7f)) {
                throw new SecurityException("provider webhook fact value is invalid");
            }
        }
    }

    private static void appendJsonString(StringBuilder target, String value) {
        Objects.requireNonNull(value, "canonical fact value");
        target.append('"');
        value.codePoints().forEach(codePoint -> {
            switch (codePoint) {
                case '"' -> target.append("\\\"");
                case '\\' -> target.append("\\\\");
                case '\b' -> target.append("\\b");
                case '\f' -> target.append("\\f");
                case '\n' -> target.append("\\n");
                case '\r' -> target.append("\\r");
                case '\t' -> target.append("\\t");
                default -> {
                    if (codePoint < 0x20) {
                        target.append(String.format("\\u%04x", codePoint));
                    } else {
                        target.appendCodePoint(codePoint);
                    }
                }
            }
        });
        target.append('"');
    }
}
