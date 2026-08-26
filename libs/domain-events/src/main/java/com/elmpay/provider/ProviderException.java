package com.elmpay.provider;

/** Classified provider failure. Unknown outcomes must never be retried as fresh money movement. */
public final class ProviderException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;
    private final boolean retryable;
    private final boolean outcomeUnknown;

    public ProviderException(String code, String message, boolean retryable, boolean outcomeUnknown) {
        super(message);
        this.code = code;
        this.retryable = retryable;
        this.outcomeUnknown = outcomeUnknown;
    }

    public String code() {
        return code;
    }

    public boolean retryable() {
        return retryable;
    }

    public boolean outcomeUnknown() {
        return outcomeUnknown;
    }
}
