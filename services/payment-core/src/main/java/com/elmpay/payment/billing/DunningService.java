package com.elmpay.payment.billing;

import com.elmpay.provider.VerifiedProviderEvidence;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded renewal recovery with deterministic schedules and explicit UNKNOWN handling. */
public final class DunningService {
    public enum Status { SCHEDULED, WAITING_PROVIDER_QUERY, RECOVERED, EXHAUSTED, PAUSED }
    public enum ProviderResult { SUCCEEDED, FAILED, UNKNOWN }
    public record Policy(List<Duration> retryDelays, Duration gracePeriod) {
        public Policy { retryDelays = List.copyOf(retryDelays); if (retryDelays.isEmpty()) throw new IllegalArgumentException("retry schedule required"); }
    }
    public record Case(String id, String tenantId, String subscriptionId, Status status, int attempts,
                       Instant nextAttemptAt, Instant graceEndsAt, String notificationKey) {}
    private final Clock clock;
    private final Policy policy;
    private final Map<String, Case> cases = new ConcurrentHashMap<>();

    private static final String DUNNING_EVIDENCE_TYPE = "PROVIDER_DUNNING_RESULT";

    public DunningService(Clock clock, Policy policy) {
        this.clock = Objects.requireNonNull(clock);
        this.policy = Objects.requireNonNull(policy);
    }

    public Case open(String tenantId, String subscriptionId) {
        Instant now = clock.instant();
        String id = UUID.randomUUID().toString();
        Case value = new Case(id, tenantId, subscriptionId, Status.SCHEDULED, 0,
                now.plus(policy.retryDelays().get(0)), now.plus(policy.gracePeriod()), "dunning:" + id + ":opened");
        cases.put(key(tenantId, id), value); return value;
    }

    public Case recordAttempt(String tenantId, String caseId, ProviderResult result,
            String provider, String providerResultDigest,
            VerifiedProviderEvidence providerEvidence) {
        Objects.requireNonNull(result, "result");
        require(provider, "provider");
        String digest = providerDigest(providerResultDigest);
        return update(tenantId, caseId, value -> {
            int attempts = value.attempts() + 1;
            requireEvidence(providerEvidence, evidenceFields(value, tenantId, provider, result,
                    digest, attempts));
            if (result == ProviderResult.SUCCEEDED)
                return copy(value, Status.RECOVERED, attempts, null);
            if (result == ProviderResult.UNKNOWN)
                return copy(value, Status.WAITING_PROVIDER_QUERY, attempts, null);
            if (attempts >= policy.retryDelays().size() || !clock.instant().isBefore(value.graceEndsAt()))
                return copy(value, Status.EXHAUSTED, attempts, null);
            return copy(value, Status.SCHEDULED, attempts, clock.instant().plus(policy.retryDelays().get(attempts)));
        });
    }

    public Case resumeAfterQuery(String tenantId, String caseId, ProviderResult result,
            String provider, String providerResultDigest,
            VerifiedProviderEvidence providerEvidence) {
        Objects.requireNonNull(result, "result");
        require(provider, "provider");
        String digest = providerDigest(providerResultDigest);
        Case value = get(tenantId, caseId);
        if (value.status() != Status.WAITING_PROVIDER_QUERY) throw new IllegalStateException("case is not awaiting provider query");
        return update(tenantId, caseId, current -> {
            requireEvidence(providerEvidence, evidenceFields(current, tenantId, provider, result,
                    digest, current.attempts()));
            if (result == ProviderResult.UNKNOWN) return current;
            if (result == ProviderResult.SUCCEEDED)
                return copy(current, Status.RECOVERED, current.attempts(), null);
            if (current.attempts() >= policy.retryDelays().size() || !clock.instant().isBefore(current.graceEndsAt()))
                return copy(current, Status.EXHAUSTED, current.attempts(), null);
            return copy(current, Status.SCHEDULED, current.attempts(),
                    clock.instant().plus(policy.retryDelays().get(current.attempts())));
        });
    }
    public Case pause(String tenantId, String caseId) { return update(tenantId, caseId, v -> copy(v, Status.PAUSED, v.attempts(), null)); }
    public Case get(String tenantId, String id) {
        Case value = cases.get(key(tenantId, id)); if (value == null) throw new SecurityException("dunning case not found"); return value;
    }
    private Case update(String tenant, String id, java.util.function.UnaryOperator<Case> op) {
        Case value = cases.computeIfPresent(key(tenant, id), (ignored, old) -> op.apply(old));
        if (value == null) throw new SecurityException("dunning case not found"); return value;
    }
    private static Case copy(Case v, Status status, int attempts, Instant next) {
        return new Case(v.id(), v.tenantId(), v.subscriptionId(), status, attempts, next, v.graceEndsAt(),
                "dunning:" + v.id() + ":" + status + ":" + attempts);
    }
    private static Map<String, String> evidenceFields(Case value, String tenantId,
            String provider, ProviderResult result, String providerResultDigest, int attempt) {
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        fields.put("tenantId", tenantId);
        fields.put("provider", provider);
        fields.put("entityId", value.id());
        fields.put("subscriptionId", value.subscriptionId());
        fields.put("attempt", Integer.toString(attempt));
        fields.put("result", result.name().toLowerCase(java.util.Locale.ROOT));
        fields.put("providerResultDigest", providerResultDigest);
        return Map.copyOf(fields);
    }
    private static void requireEvidence(VerifiedProviderEvidence evidence,
            Map<String, String> expectedFields) {
        if (evidence == null || !DUNNING_EVIDENCE_TYPE.equals(evidence.evidenceType())
                || evidence.fields().size() != expectedFields.size())
            throw new SecurityException("verified provider evidence is required");
        for (Map.Entry<String, String> expected : expectedFields.entrySet()) {
            if (!expected.getValue().equals(evidence.fields().get(expected.getKey())))
                throw new SecurityException("provider evidence binding mismatch");
        }
    }
    private static String providerDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("provider result digest must be lowercase SHA-256 hex");
        return value;
    }
    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }
    private static String key(String tenant, String id) { return tenant + "\u0000" + id; }
}
