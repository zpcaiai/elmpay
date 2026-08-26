package com.elmpay.payment;

public enum OutcomeClass {
    SUCCEEDED(true, false),
    FAILED_FINAL(true, false),
    FAILED_RETRYABLE(true, true),
    UNKNOWN(false, false);

    private final boolean finalOutcome;
    private final boolean retryable;

    OutcomeClass(boolean finalOutcome, boolean retryable) {
        this.finalOutcome = finalOutcome;
        this.retryable = retryable;
    }

    public boolean finalOutcome() {
        return finalOutcome;
    }

    public boolean retryable() {
        return retryable;
    }
}
