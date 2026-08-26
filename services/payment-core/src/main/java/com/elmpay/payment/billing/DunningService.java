package com.elmpay.payment.billing;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded renewal recovery with deterministic schedules and explicit UNKNOWN handling. */
public final class DunningService {
    public enum Status { SCHEDULED, WAITING_PROVIDER_QUERY, RECOVERED, EXHAUSTED, PAUSED }
    public record Policy(List<Duration> retryDelays, Duration gracePeriod) {
        public Policy { retryDelays = List.copyOf(retryDelays); if (retryDelays.isEmpty()) throw new IllegalArgumentException("retry schedule required"); }
    }
    public record Case(String id, String tenantId, String subscriptionId, Status status, int attempts,
                       Instant nextAttemptAt, Instant graceEndsAt, String notificationKey) {}
    private final Clock clock;
    private final Policy policy;
    private final Map<String, Case> cases = new ConcurrentHashMap<>();

    public DunningService(Clock clock, Policy policy) { this.clock = java.util.Objects.requireNonNull(clock); this.policy = policy; }

    public Case open(String tenantId, String subscriptionId) {
        Instant now = clock.instant();
        String id = UUID.randomUUID().toString();
        Case value = new Case(id, tenantId, subscriptionId, Status.SCHEDULED, 0,
                now.plus(policy.retryDelays().get(0)), now.plus(policy.gracePeriod()), "dunning:" + id + ":opened");
        cases.put(key(tenantId, id), value); return value;
    }

    public Case recordAttempt(String tenantId, String caseId, boolean verifiedSuccess, boolean definitiveFailure) {
        return update(tenantId, caseId, value -> {
            if (verifiedSuccess) return copy(value, Status.RECOVERED, value.attempts() + 1, null);
            if (!definitiveFailure) return copy(value, Status.WAITING_PROVIDER_QUERY, value.attempts() + 1, null);
            int attempts = value.attempts() + 1;
            if (attempts >= policy.retryDelays().size() || !clock.instant().isBefore(value.graceEndsAt()))
                return copy(value, Status.EXHAUSTED, attempts, null);
            return copy(value, Status.SCHEDULED, attempts, clock.instant().plus(policy.retryDelays().get(attempts)));
        });
    }

    public Case resumeAfterQuery(String tenantId, String caseId, boolean providerConfirmedFailure) {
        Case value = get(tenantId, caseId);
        if (value.status() != Status.WAITING_PROVIDER_QUERY) throw new IllegalStateException("case is not awaiting provider query");
        return update(tenantId, caseId, current -> {
            if (!providerConfirmedFailure) return copy(current, Status.RECOVERED, current.attempts(), null);
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
    private static String key(String tenant, String id) { return tenant + "\u0000" + id; }
}
