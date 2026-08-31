package com.elmpay.gateway;

/** Fail-closed domain rejection safe to map to a bounded internal error code. */
public final class AdminActionException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public AdminActionException(String code, String message) {
        super(message);
        if (code == null || !code.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("admin action error code is invalid");
        }
        this.code = code;
    }

    public AdminActionException(String code, String message, Throwable cause) {
        super(message, cause);
        if (code == null || !code.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("admin action error code is invalid");
        }
        this.code = code;
    }

    public String code() {
        return code;
    }
}
