package com.elmpay.idempotency;

import java.util.Objects;

public record IdempotencyClaim(Status status, String ownerToken, StoredResult replay) {
    public enum Status {
        OWNED,
        REPLAY,
        BUSY,
        UNKNOWN_OUTCOME
    }

    public IdempotencyClaim {
        Objects.requireNonNull(status, "status");
        if (status == Status.OWNED && (ownerToken == null || ownerToken.isBlank())) {
            throw new IllegalArgumentException("owned claim requires owner token");
        }
        if (status == Status.REPLAY && replay == null) {
            throw new IllegalArgumentException("replay claim requires stored result");
        }
    }
}
