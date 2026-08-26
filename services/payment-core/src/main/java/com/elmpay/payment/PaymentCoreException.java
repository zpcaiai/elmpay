package com.elmpay.payment;

public final class PaymentCoreException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public PaymentCoreException(String code, String message) {
        super(message);
        this.code = code;
    }

    public PaymentCoreException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
