package com.elmpay.payment;

public enum AttemptState {
    INITIATED,
    PENDING,
    SUCCEEDED,
    FAILED,
    UNKNOWN;

    public boolean finalState() {
        return this == SUCCEEDED || this == FAILED;
    }
}
