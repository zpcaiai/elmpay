package com.elmpay.merchant;

public final class RoutingException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public RoutingException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
