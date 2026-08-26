package com.elmpay.payment.checkout;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/** Deterministic, explainable payment-method eligibility and fallback. */
public final class CapabilityResolver {
    public record Capability(String method, Set<String> regions, Set<String> currencies,
                             Set<String> deviceClasses, boolean merchantEnabled, int priority) {
        public Capability {
            if (method == null || method.isBlank()) throw new IllegalArgumentException("method required");
            regions = normalized(regions); currencies = normalized(currencies); deviceClasses = normalized(deviceClasses);
        }
    }
    public record Health(boolean available, Instant observedAt) {}
    public record Context(String region, String currency, String deviceClass, Instant now, Duration maxHealthAge) {}
    public record Decision(String method, boolean eligible, List<String> reasons) {}

    public List<Decision> resolve(Collection<Capability> capabilities,
                                  java.util.Map<String, Health> healthByMethod,
                                  Context context) {
        Objects.requireNonNull(capabilities, "capabilities");
        Objects.requireNonNull(healthByMethod, "healthByMethod");
        Objects.requireNonNull(context, "context");
        List<Decision> decisions = new ArrayList<>();
        for (Capability capability : capabilities) {
            List<String> reasons = new ArrayList<>();
            if (!capability.merchantEnabled()) reasons.add("MERCHANT_DISABLED");
            if (!capability.regions().contains(norm(context.region()))) reasons.add("REGION_UNSUPPORTED");
            if (!capability.currencies().contains(norm(context.currency()))) reasons.add("CURRENCY_UNSUPPORTED");
            if (!capability.deviceClasses().contains(norm(context.deviceClass()))) reasons.add("DEVICE_UNSUPPORTED");
            Health health = healthByMethod.get(capability.method());
            if (health == null) reasons.add("HEALTH_UNKNOWN");
            else if (health.observedAt().plus(context.maxHealthAge()).isBefore(context.now())) reasons.add("HEALTH_STALE");
            else if (!health.available()) reasons.add("PROVIDER_UNAVAILABLE");
            decisions.add(new Decision(capability.method(), reasons.isEmpty(), List.copyOf(reasons)));
        }
        decisions.sort(Comparator
                .comparing((Decision d) -> !d.eligible())
                .thenComparingInt(d -> capabilities.stream().filter(c -> c.method().equals(d.method()))
                        .findFirst().orElseThrow().priority())
                .thenComparing(Decision::method));
        return List.copyOf(decisions);
    }

    public String select(Collection<Capability> capabilities, java.util.Map<String, Health> health, Context context) {
        return resolve(capabilities, health, context).stream().filter(Decision::eligible).findFirst()
                .map(Decision::method).orElseThrow(() -> new IllegalStateException("NO_ELIGIBLE_PAYMENT_METHOD"));
    }

    private static Set<String> normalized(Set<String> values) {
        if (values == null || values.isEmpty()) throw new IllegalArgumentException("capability set must not be empty");
        return values.stream().map(CapabilityResolver::norm).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
    private static String norm(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("capability value is required");
        return value.toUpperCase(Locale.ROOT);
    }
}
