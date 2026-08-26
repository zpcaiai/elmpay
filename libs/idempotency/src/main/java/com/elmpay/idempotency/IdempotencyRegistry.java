package com.elmpay.idempotency;

import java.time.Duration;
import java.util.UUID;

public interface IdempotencyRegistry {
    IdempotencyClaim claim(UUID tenantId, String operation, String key, String requestHash,
            Duration leaseDuration, Duration retention);

    void complete(UUID tenantId, String operation, String key, String ownerToken, StoredResult result);

    void markUnknown(UUID tenantId, String operation, String key, String ownerToken, String reasonCode);
}
