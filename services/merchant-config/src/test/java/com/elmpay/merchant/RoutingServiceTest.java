package com.elmpay.merchant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.security.SecretReference;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class RoutingServiceTest {
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("00000000-0000-0000-0000-000000000003");

    @Test
    void selectsLowestPriorityActiveCompatibleRoute() {
        ProviderRoute slower = route("stripe", 20, AccountStatus.ACTIVE);
        ProviderRoute preferred = route("paypal", 10, AccountStatus.ACTIVE);
        RoutingService service = new RoutingService(repository(List.of(slower, preferred)));

        assertEquals("paypal", service.select(request()).account().provider());
    }

    @Test
    void failsClosedWhenOnlySuspendedAccountsExist() {
        RoutingService service = new RoutingService(
                repository(List.of(route("stripe", 1, AccountStatus.SUSPENDED))));
        assertThrows(RoutingException.class, () -> service.select(request()));
    }

    private static ProviderRoute route(String provider, int priority, AccountStatus status) {
        ProviderAccount account = new ProviderAccount(UUID.randomUUID(), TENANT, PROJECT, MERCHANT,
                provider, "sandbox", "merchant-1", SecretReference.parse("vault://payments/key"),
                "v1", status);
        ProviderCapability capability = new ProviderCapability(provider, "card", Set.of("USD"),
                Set.of("US"), true, true, true, true);
        return new ProviderRoute(account, capability, priority, "routes-v1");
    }

    private static RoutingRequest request() {
        return new RoutingRequest(TENANT, PROJECT, MERCHANT, "card", "USD", "US", 1_000,
                "intent-1");
    }

    private static MerchantConfigurationRepository repository(List<ProviderRoute> routes) {
        return new MerchantConfigurationRepository() {
            @Override
            public Optional<ProviderAccount> findAccount(UUID tenantId, UUID projectId,
                    UUID accountId) {
                return Optional.empty();
            }

            @Override
            public List<ProviderRoute> eligibleRoutes(RoutingRequest request) {
                return routes;
            }
        };
    }
}
