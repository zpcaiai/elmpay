package com.elmpay.merchant;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public record ProviderCapability(String provider, String method, Set<String> currencies,
        Set<String> regions, boolean authorizationCapture, boolean partialCapture,
        boolean partialRefund, boolean subscriptions) {
    public ProviderCapability {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(currencies, "currencies");
        Objects.requireNonNull(regions, "regions");
        provider = provider.toLowerCase(Locale.ROOT);
        method = method.toLowerCase(Locale.ROOT);
        currencies = currencies.stream().map(value -> value.toUpperCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        regions = regions.stream().map(value -> value.toUpperCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (provider.isBlank() || method.isBlank() || currencies.isEmpty() || regions.isEmpty()) {
            throw new IllegalArgumentException("invalid provider capability");
        }
    }

    public boolean supports(String requestedMethod, String currency, String region) {
        return method.equalsIgnoreCase(requestedMethod)
                && currencies.contains(currency.toUpperCase(Locale.ROOT))
                && regions.contains(region.toUpperCase(Locale.ROOT));
    }
}
