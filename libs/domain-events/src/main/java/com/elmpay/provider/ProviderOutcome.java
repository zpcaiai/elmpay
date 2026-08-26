package com.elmpay.provider;

/** Normalized provider result; UNKNOWN always requires a server-side query. */
public enum ProviderOutcome {
    REQUIRES_ACTION,
    AUTHORIZED,
    SUCCEEDED,
    DECLINED,
    FAILED,
    CANCELED,
    UNKNOWN
}
