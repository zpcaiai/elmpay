package com.elmpay.payment.provider;

import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/** Explicit account set whose availability controls production readiness. */
public record ProviderReadinessBinding(String provider, UUID tenantId, UUID projectId,
        UUID providerAccountId) {
    public ProviderReadinessBinding {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        provider = provider.toLowerCase(Locale.ROOT);
        if (!provider.matches("[a-z][a-z0-9_]{1,31}")) {
            throw new IllegalArgumentException("provider has an invalid format");
        }
    }
}
