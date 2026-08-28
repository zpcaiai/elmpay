package com.elmpay.payment.checkout;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Explicit local/test capability source. Production must use its durable read model. */
public final class ConfiguredCheckoutCapabilitySource implements CheckoutCapabilitySource {
    private final Set<String> configuredMethods;

    public ConfiguredCheckoutCapabilitySource(Set<String> configuredMethods) {
        if (configuredMethods == null || configuredMethods.isEmpty()) {
            throw new IllegalArgumentException("configured checkout methods are required");
        }
        this.configuredMethods = configuredMethods.stream()
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    @Override
    public List<CapabilityResolver.Decision> resolve(Request request) {
        return request.signedMethods().stream().map(method -> configuredMethods.contains(method)
                        ? new CapabilityResolver.Decision(method, true, List.of())
                        : new CapabilityResolver.Decision(method, false,
                                List.of("METHOD_NOT_CONFIGURED")))
                .sorted(Comparator.comparing((CapabilityResolver.Decision decision) ->
                        !decision.eligible()).thenComparing(CapabilityResolver.Decision::method))
                .toList();
    }
}
