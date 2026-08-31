package com.elmpay.tenant;

import java.time.Instant;
import java.util.UUID;

/** Opaque authority fact that can only be created by {@link TenantEvidenceVerifier}. */
public final class VerifiedTenantEvidence {
    private final UUID tenantId;
    private final TenantEvidenceType evidenceType;
    private final String authority;
    private final String decisionReference;
    private final String payloadDigest;
    private final String receiptDigest;
    private final String signerIdentity;
    private final String keyId;
    private final Instant issuedAt;
    private final Instant expiresAt;

    VerifiedTenantEvidence(UUID tenantId, TenantEvidenceType evidenceType, String authority,
            String decisionReference, String payloadDigest, String receiptDigest,
            String signerIdentity, String keyId, Instant issuedAt, Instant expiresAt) {
        this.tenantId = tenantId;
        this.evidenceType = evidenceType;
        this.authority = authority;
        this.decisionReference = decisionReference;
        this.payloadDigest = payloadDigest;
        this.receiptDigest = receiptDigest;
        this.signerIdentity = signerIdentity;
        this.keyId = keyId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public UUID tenantId() {
        return tenantId;
    }

    public TenantEvidenceType evidenceType() {
        return evidenceType;
    }

    public String authority() {
        return authority;
    }

    public String decisionReference() {
        return decisionReference;
    }

    public String payloadDigest() {
        return payloadDigest;
    }

    public String receiptDigest() {
        return receiptDigest;
    }

    public String signerIdentity() {
        return signerIdentity;
    }

    public String keyId() {
        return keyId;
    }

    public Instant issuedAt() {
        return issuedAt;
    }

    public Instant expiresAt() {
        return expiresAt;
    }
}
