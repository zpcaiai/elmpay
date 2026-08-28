package com.elmpay.merchant;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MerchantConfigurationRepository {
    Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId, UUID accountId);

    /** Webhook lookup is still tenant-bound; account UUIDs are never accepted cross-tenant. */
    default Optional<ProviderAccount> findAccount(UUID tenantId, UUID accountId) {
        return Optional.empty();
    }

    List<ProviderRoute> eligibleRoutes(RoutingRequest request);

    /** Persist the exact replayable decision after deterministic selection. */
    default void recordRoutingDecision(RoutingRequest request, ProviderRoute selected,
            List<ProviderRoute> evaluatedRoutes) {
        // Non-production repositories may remain stateless. The JDBC implementation is durable.
    }
}
