package com.elmpay.gateway;

import com.elmpay.merchant.AccountStatus;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.merchant.ProviderCapability;
import com.elmpay.merchant.ProviderRoute;
import com.elmpay.merchant.RoutingRequest;
import com.elmpay.security.SecretReference;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Explicit local-sandbox configuration. It is never enabled implicitly. */
public final class LocalMerchantConfigurationRepository
        implements MerchantConfigurationRepository {
    private final ConcurrentHashMap<UUID, ProviderAccount> accounts = new ConcurrentHashMap<>();

    @Override
    public Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId, UUID accountId) {
        ProviderAccount account = accounts.get(accountId);
        return account != null && account.tenantId().equals(tenantId)
                && account.projectId().equals(projectId) ? Optional.of(account) : Optional.empty();
    }

    @Override
    public Optional<ProviderAccount> findAccount(UUID tenantId, UUID accountId) {
        ProviderAccount account = accounts.get(accountId);
        return account != null && account.tenantId().equals(tenantId)
                ? Optional.of(account) : Optional.empty();
    }

    @Override
    public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
        String identity = request.tenantId() + ":" + request.projectId() + ":" + request.merchantId();
        UUID accountId = UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8));
        ProviderAccount account = accounts.computeIfAbsent(accountId, ignored -> new ProviderAccount(
                accountId, request.tenantId(), request.projectId(), request.merchantId(), "stripe",
                "sandbox", "local-sandbox", SecretReference.parse("vault://local/sandbox"),
                "local-v1", AccountStatus.ACTIVE));
        ProviderCapability capability = new ProviderCapability("stripe", request.method(),
                Set.of(request.currency()), Set.of(request.region()), true, true, true, true);
        return List.of(new ProviderRoute(account, capability, 1, "local-sandbox-v1"));
    }
}
