package com.elmpay.gateway;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record ApiPrincipal(String id, UUID tenantId, UUID projectId, UUID merchantId,
        Set<String> scopes) {
    public static final String PAYMENTS_READ = "payments.read";
    public static final String PAYMENTS_WRITE = "payments.write";
    public static final Set<String> SUPPORTED_SCOPES = Set.of(PAYMENTS_READ, PAYMENTS_WRITE);

    public ApiPrincipal {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(scopes, "scopes");
        scopes = Set.copyOf(scopes);
        if (id.isBlank() || scopes.isEmpty() || !SUPPORTED_SCOPES.containsAll(scopes)) {
            throw new IllegalArgumentException("principal id is required");
        }
    }

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }
}
