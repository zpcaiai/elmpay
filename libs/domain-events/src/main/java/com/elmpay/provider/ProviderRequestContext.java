package com.elmpay.provider;

import java.util.Objects;
import java.util.UUID;

public record ProviderRequestContext(UUID tenantId, UUID projectId, UUID merchantAccountId,
        String idempotencyKey, String correlationId, String credentialVersion) {
    public ProviderRequestContext {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(merchantAccountId, "merchantAccountId");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(credentialVersion, "credentialVersion");
        if (idempotencyKey.length() < 16 || idempotencyKey.length() > 128) {
            throw new IllegalArgumentException("invalid provider idempotency key");
        }
    }
}
