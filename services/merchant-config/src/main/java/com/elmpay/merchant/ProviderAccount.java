package com.elmpay.merchant;

import com.elmpay.security.SecretReference;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Tenant/project-bound provider identity. Only an external secret reference is retained. */
public record ProviderAccount(UUID id, UUID tenantId, UUID projectId, UUID merchantId,
        String provider, String environment, String providerMerchantId,
        SecretReference credentialReference, String credentialVersion, AccountStatus status) {
    private static final Set<String> PROVIDERS = Set.of(
            "wechat", "alipay", "stripe", "paypal", "apple_pay");
    private static final Set<String> ENVIRONMENTS = Set.of("sandbox", "production");

    public ProviderAccount {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(providerMerchantId, "providerMerchantId");
        Objects.requireNonNull(credentialReference, "credentialReference");
        Objects.requireNonNull(credentialVersion, "credentialVersion");
        Objects.requireNonNull(status, "status");
        provider = provider.toLowerCase(Locale.ROOT);
        environment = environment.toLowerCase(Locale.ROOT);
        if (!PROVIDERS.contains(provider) || !ENVIRONMENTS.contains(environment)
                || providerMerchantId.isBlank() || credentialVersion.isBlank()) {
            throw new IllegalArgumentException("invalid provider account binding");
        }
    }
}
