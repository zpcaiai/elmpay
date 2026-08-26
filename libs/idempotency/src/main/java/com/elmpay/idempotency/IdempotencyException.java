package com.elmpay.idempotency;

public final class IdempotencyException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public IdempotencyException(String code, String message) {
        super(message);
        this.code = code;
    }

    public IdempotencyException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
