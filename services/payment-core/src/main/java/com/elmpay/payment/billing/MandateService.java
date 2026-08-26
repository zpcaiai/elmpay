package com.elmpay.payment.billing;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Stores consent and opaque PSP token references; raw card data is rejected. */
public final class MandateService {
    public enum Status { ACTIVE, REVOKED }
    public record Mandate(String id, String tenantId, String customerId, String provider,
                          String providerMandateReference, String paymentMethodReference,
                          String purpose, long maximumAmountMinor, String currency,
                          String consentDigest, Instant consentedAt, Status status, Instant revokedAt) {}
    private final Clock clock;
    private final Map<String, Mandate> mandates = new ConcurrentHashMap<>();

    public MandateService(Clock clock) { this.clock = java.util.Objects.requireNonNull(clock); }

    public Mandate create(String tenantId, String customerId, String provider, String providerMandateReference,
                          String paymentMethodReference, String purpose, long maximumAmountMinor,
                          String currency, String consentDigest) {
        for (String value : new String[]{tenantId, customerId, provider, providerMandateReference,
                paymentMethodReference, purpose, currency, consentDigest}) require(value);
        rejectCardData(paymentMethodReference);
        if (maximumAmountMinor <= 0) throw new IllegalArgumentException("mandate maximum must be positive");
        String id = UUID.randomUUID().toString();
        Mandate value = new Mandate(id, tenantId, customerId, provider, providerMandateReference,
                paymentMethodReference, purpose, maximumAmountMinor, currency, consentDigest,
                clock.instant(), Status.ACTIVE, null);
        mandates.put(key(tenantId, id), value);
        return value;
    }

    public void authorize(String tenantId, String mandateId, String purpose, long amountMinor, String currency) {
        Mandate mandate = get(tenantId, mandateId);
        if (mandate.status() != Status.ACTIVE) throw new SecurityException("mandate is revoked");
        if (!mandate.purpose().equals(purpose) || !mandate.currency().equals(currency)
                || amountMinor <= 0 || amountMinor > mandate.maximumAmountMinor()) {
            throw new SecurityException("charge is outside mandate scope");
        }
    }

    public Mandate revoke(String tenantId, String mandateId) {
        String key = key(tenantId, mandateId);
        Mandate result = mandates.computeIfPresent(key, (ignored, value) -> value.status() == Status.REVOKED ? value
                : new Mandate(value.id(), value.tenantId(), value.customerId(), value.provider(),
                value.providerMandateReference(), value.paymentMethodReference(), value.purpose(),
                value.maximumAmountMinor(), value.currency(), value.consentDigest(), value.consentedAt(),
                Status.REVOKED, clock.instant()));
        if (result == null) throw new SecurityException("mandate not found");
        return result;
    }

    public Mandate get(String tenantId, String mandateId) {
        Mandate value = mandates.get(key(tenantId, mandateId));
        if (value == null) throw new SecurityException("mandate not found");
        return value;
    }
    private static void rejectCardData(String value) {
        String compact = value.replaceAll("[ -]", "");
        if (compact.matches(".*\\d{12,19}.*") || value.toLowerCase(java.util.Locale.ROOT).contains("cvv")) {
            throw new SecurityException("raw card data is forbidden");
        }
    }
    private static String key(String tenant, String id) { return tenant + "\u0000" + id; }
    private static void require(String value) { if (value == null || value.isBlank()) throw new IllegalArgumentException("required value missing"); }
}
