package com.elmpay.payment.refund;

/** Durable refund states. UNKNOWN always requires a provider-side query. */
public enum RefundStatus {
    APPROVAL_PENDING,
    PROCESSING,
    UNKNOWN,
    SUCCEEDED,
    FAILED,
    CANCELED;

    public boolean finalState() {
        return this == SUCCEEDED || this == FAILED || this == CANCELED;
    }

    public boolean holdsReservation() {
        return this == APPROVAL_PENDING || this == PROCESSING || this == UNKNOWN
                || this == SUCCEEDED;
    }
}
