package com.elmpay.payment.refund;

import java.util.Locale;

/** Public refund reason vocabulary from the versioned API contract. */
public enum RefundReason {
    CUSTOMER_REQUEST,
    DUPLICATE,
    FRAUDULENT,
    SERVICE_FAILURE,
    OTHER;

    public String wireValue() {
        return name().toLowerCase(Locale.ROOT);
    }
}
