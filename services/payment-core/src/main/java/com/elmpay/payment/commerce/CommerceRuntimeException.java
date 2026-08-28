package com.elmpay.payment.commerce;

import java.io.Serial;

/** Classified fail-closed commerce runtime error without leaking SQL or provider details. */
public final class CommerceRuntimeException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;
    private final String code;

    public CommerceRuntimeException(String code, String message) {
        super(message);
        this.code = code;
    }

    public CommerceRuntimeException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
