package com.elmpay.risk;

/** Product mutations that require a synchronous, fail-closed risk decision. */
public enum RiskOperation {
    PAYMENT_CREATE,
    PAYMENT_CONFIRM,
    PAYMENT_CAPTURE,
    REFUND_REQUEST,
    CREDENTIAL_CHANGE,
    PAYMENT_METHOD_ADD,
    PRIVILEGE_ELEVATION
}
