package com.elmpay.tenant;

/** Closed set of authority facts accepted by the tenant lifecycle. */
public enum TenantEvidenceType {
    KYB_VERIFIED,
    CONTRACT_SIGNED,
    SETTLEMENT_COMPLETE,
    RETENTION_PERIOD_STARTED,
    KEK_DESTROYED,
    UNKNOWN
}
