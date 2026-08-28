package com.elmpay.risk.identity;

import java.util.Map;
import java.util.Objects;

/** Idempotent, tenant-scoped identity mutation descriptor; attributes must be digests/labels. */
public record IdentityMutationCommand(String tenantId, String requestId, String subjectId,
        Map<String, String> attributes) {
    public IdentityMutationCommand {
        requireText(tenantId, "tenantId");
        requireText(requestId, "requestId");
        requireText(subjectId, "subjectId");
        Objects.requireNonNull(attributes, "attributes");
        attributes = Map.copyOf(attributes);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
