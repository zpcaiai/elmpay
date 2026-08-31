package com.elmpay.provider;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record WebhookRequest(UUID tenantId, UUID merchantAccountId, Map<String, String> headers,
        byte[] rawBody, Instant receivedAt) implements AutoCloseable {
    public WebhookRequest {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(merchantAccountId, "merchantAccountId");
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(rawBody, "rawBody");
        Objects.requireNonNull(receivedAt, "receivedAt");
        if (rawBody.length == 0 || rawBody.length > 1_048_576) {
            throw new IllegalArgumentException("webhook body size is invalid");
        }
        headers = Map.copyOf(headers);
        rawBody = rawBody.clone();
    }

    @Override
    public byte[] rawBody() {
        return rawBody.clone();
    }

    /** Erases the request-owned body copy after synchronous signature verification. */
    @Override
    public void close() {
        Arrays.fill(rawBody, (byte) 0);
    }
}
