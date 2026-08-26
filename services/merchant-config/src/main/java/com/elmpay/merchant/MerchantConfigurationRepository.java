package com.elmpay.merchant;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MerchantConfigurationRepository {
    Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId, UUID accountId);

    List<ProviderRoute> eligibleRoutes(RoutingRequest request);
}
