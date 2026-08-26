package com.elmpay.payment;

public enum IntentState {
    CREATED,
    REQUIRES_ACTION,
    AUTHORIZED,
    CAPTURED,
    FAILED,
    CANCELED,
    EXPIRED;

    public boolean terminal() {
        return this == CAPTURED || this == FAILED || this == CANCELED || this == EXPIRED;
    }
}
