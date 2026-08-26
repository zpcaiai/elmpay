package com.elmpay.payment.billing;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Plans, subscriptions, idempotent usage and renewal state transitions. */
public final class SubscriptionService {
    public enum Status { TRIALING, ACTIVE, PAST_DUE, PAUSED, CANCELED }
    public record Plan(String id, String tenantId, long unitAmountMinor, String currency,
                       Duration billingPeriod, Duration trialPeriod, boolean metered) {}
    public record Subscription(String id, String tenantId, String customerId, String planId, String mandateId,
                               Status status, Instant periodStart, Instant periodEnd, long usage,
                               Instant cancelAt, long version) {}
    private final Clock clock;
    private final Map<String, Plan> plans = new ConcurrentHashMap<>();
    private final Map<String, Subscription> subscriptions = new ConcurrentHashMap<>();
    private final Map<String, Long> usageInbox = new ConcurrentHashMap<>();

    public SubscriptionService(Clock clock) { this.clock = java.util.Objects.requireNonNull(clock); }

    public Plan addPlan(Plan plan) {
        if (plan.unitAmountMinor() < 0 || plan.billingPeriod().isZero() || plan.billingPeriod().isNegative())
            throw new IllegalArgumentException("invalid plan");
        Plan existing = plans.putIfAbsent(key(plan.tenantId(), plan.id()), plan);
        if (existing != null && !existing.equals(plan)) throw new IllegalStateException("plan version conflict");
        return existing == null ? plan : existing;
    }

    public Subscription subscribe(String tenantId, String customerId, String planId, String mandateId) {
        Plan plan = requirePlan(tenantId, planId);
        Instant now = clock.instant();
        Status status = plan.trialPeriod().isZero() ? Status.ACTIVE : Status.TRIALING;
        Instant end = now.plus(status == Status.TRIALING ? plan.trialPeriod() : plan.billingPeriod());
        Subscription value = new Subscription(UUID.randomUUID().toString(), tenantId, customerId, planId,
                mandateId, status, now, end, 0L, null, 1L);
        subscriptions.put(key(tenantId, value.id()), value);
        return value;
    }

    public synchronized Subscription recordUsage(String tenantId, String subscriptionId, String idempotencyKey, long quantity) {
        if (quantity <= 0) throw new IllegalArgumentException("usage quantity must be positive");
        String inboxKey = key(tenantId, subscriptionId) + "\u0000" + idempotencyKey;
        Long previous = usageInbox.get(inboxKey);
        if (previous != null && previous != quantity) throw new IllegalStateException("usage idempotency conflict");
        if (previous != null) return get(tenantId, subscriptionId);
        Subscription updated = update(tenantId, subscriptionId, value -> copy(value, value.status(),
                Math.addExact(value.usage(), quantity), value.cancelAt()));
        usageInbox.put(inboxKey, quantity);
        return updated;
    }

    public Subscription renewalResult(String tenantId, String subscriptionId, boolean verifiedSuccess, boolean definitiveFailure) {
        return update(tenantId, subscriptionId, value -> {
            if (verifiedSuccess) {
                Plan plan = requirePlan(tenantId, value.planId());
                Instant start = value.periodEnd();
                return new Subscription(value.id(), value.tenantId(), value.customerId(), value.planId(), value.mandateId(),
                        Status.ACTIVE, start, start.plus(plan.billingPeriod()), 0L, value.cancelAt(), value.version() + 1);
            }
            if (definitiveFailure) return copy(value, Status.PAST_DUE, value.usage(), value.cancelAt());
            return value; // unknown outcomes never infer failure or retry a charge here
        });
    }

    public Subscription scheduleCancellation(String tenantId, String subscriptionId, Instant effectiveAt) {
        return update(tenantId, subscriptionId, value -> {
            if (effectiveAt.isBefore(clock.instant()) || effectiveAt.isAfter(value.periodEnd()))
                throw new IllegalArgumentException("cancellation must fall in the current period");
            return copy(value, value.status(), value.usage(), effectiveAt);
        });
    }

    public Subscription applyDueCancellation(String tenantId, String subscriptionId) {
        return update(tenantId, subscriptionId, value -> value.cancelAt() != null && !clock.instant().isBefore(value.cancelAt())
                ? copy(value, Status.CANCELED, value.usage(), value.cancelAt()) : value);
    }

    public Subscription get(String tenantId, String subscriptionId) {
        Subscription value = subscriptions.get(key(tenantId, subscriptionId));
        if (value == null) throw new SecurityException("subscription not found");
        return value;
    }
    private Subscription update(String tenantId, String id, java.util.function.UnaryOperator<Subscription> op) {
        Subscription result = subscriptions.computeIfPresent(key(tenantId, id), (ignored, value) -> op.apply(value));
        if (result == null) throw new SecurityException("subscription not found");
        return result;
    }
    private Plan requirePlan(String tenantId, String planId) {
        Plan value = plans.get(key(tenantId, planId));
        if (value == null) throw new IllegalArgumentException("plan not found");
        return value;
    }
    private static Subscription copy(Subscription value, Status status, long usage, Instant cancelAt) {
        return new Subscription(value.id(), value.tenantId(), value.customerId(), value.planId(), value.mandateId(),
                status, value.periodStart(), value.periodEnd(), usage, cancelAt, value.version() + 1);
    }
    private static String key(String tenant, String id) { return tenant + "\u0000" + id; }
}
