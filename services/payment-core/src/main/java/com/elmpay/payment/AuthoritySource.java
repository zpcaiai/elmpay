package com.elmpay.payment;

/** Only these server-controlled sources may establish a successful money state. */
public enum AuthoritySource {
    MERCHANT_REQUEST(false),
    SCHEDULER(false),
    VERIFIED_PROVIDER_EVENT(true),
    SERVER_SIDE_PROVIDER_RESULT(true),
    RECONCILIATION(true);

    private final boolean authoritativeForSuccess;

    AuthoritySource(boolean authoritativeForSuccess) {
        this.authoritativeForSuccess = authoritativeForSuccess;
    }

    public boolean authoritativeForSuccess() {
        return authoritativeForSuccess;
    }
}
