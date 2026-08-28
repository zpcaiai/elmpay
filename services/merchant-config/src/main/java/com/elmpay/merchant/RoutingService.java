package com.elmpay.merchant;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Deterministic, fail-closed provider routing. */
public final class RoutingService {
    private final MerchantConfigurationRepository repository;

    public RoutingService(MerchantConfigurationRepository repository) {
        this.repository = Objects.requireNonNull(repository, "repository");
    }

    public ProviderRoute select(RoutingRequest request) {
        List<ProviderRoute> routes = repository.eligibleRoutes(request).stream()
                .filter(route -> route.account().status().permitsNewPayments())
                .filter(route -> route.capability().supports(
                        request.method(), request.currency(), request.region()))
                .sorted(Comparator.comparingInt(ProviderRoute::priority)
                        .thenComparing(route -> route.account().provider())
                        .thenComparing(route -> route.account().id()))
                .toList();
        if (routes.isEmpty()) {
            throw new RoutingException("NO_ELIGIBLE_PROVIDER",
                    "no active provider account satisfies the immutable payment constraints");
        }
        ProviderRoute selected = routes.getFirst();
        repository.recordRoutingDecision(request, selected, routes);
        return selected;
    }
}
