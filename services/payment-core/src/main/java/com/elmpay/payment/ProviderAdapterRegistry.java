package com.elmpay.payment;

import com.elmpay.provider.ProviderAdapter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class ProviderAdapterRegistry {
    private final Map<String, ProviderAdapter> adapters;

    public ProviderAdapterRegistry(List<ProviderAdapter> adapters) {
        Objects.requireNonNull(adapters, "adapters");
        Map<String, ProviderAdapter> byName = new HashMap<>();
        for (ProviderAdapter adapter : adapters) {
            String name = adapter.provider().toLowerCase(Locale.ROOT);
            if (byName.putIfAbsent(name, adapter) != null) {
                throw new IllegalArgumentException("duplicate provider adapter: " + name);
            }
        }
        this.adapters = Map.copyOf(byName);
    }

    public ProviderAdapter require(String provider) {
        ProviderAdapter adapter = adapters.get(provider.toLowerCase(Locale.ROOT));
        if (adapter == null) {
            throw new PaymentCoreException("PROVIDER_NOT_CONFIGURED",
                    "provider adapter is not configured");
        }
        return adapter;
    }
}
