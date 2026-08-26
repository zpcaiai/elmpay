package com.elmpay.idempotency;

import java.util.Objects;

public record StoredResult(int statusCode, String contentType, byte[] body) {
    public StoredResult {
        Objects.requireNonNull(contentType, "contentType");
        Objects.requireNonNull(body, "body");
        if (statusCode < 100 || statusCode > 599 || body.length > 1_048_576) {
            throw new IllegalArgumentException("invalid stored idempotency response");
        }
        body = body.clone();
    }

    @Override
    public byte[] body() {
        return body.clone();
    }
}
