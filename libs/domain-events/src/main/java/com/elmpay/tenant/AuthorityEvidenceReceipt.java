package com.elmpay.tenant;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** A short-lived Ed25519 authority receipt; no caller-supplied verification flag exists. */
public record AuthorityEvidenceReceipt(UUID tenantId, TenantEvidenceType evidenceType,
        String authority, String decisionReference, String payloadDigest, Instant issuedAt,
        Instant expiresAt, String nonce, String keyId, byte[] signature) {
    private static final Pattern AUTHORITY =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}");
    private static final Pattern REFERENCE =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/-]{3,255}");
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9._:-]{16,160}");
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

    public AuthorityEvidenceReceipt {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(evidenceType, "evidenceType");
        if (evidenceType == TenantEvidenceType.UNKNOWN) {
            throw new IllegalArgumentException("unknown tenant evidence is not actionable");
        }
        require(AUTHORITY, authority, "authority");
        require(REFERENCE, decisionReference, "decisionReference");
        require(DIGEST, payloadDigest, "payloadDigest");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        require(NONCE, nonce, "nonce");
        require(KEY_ID, keyId, "keyId");
        signature = Objects.requireNonNull(signature, "signature").clone();
        if (signature.length != 64) {
            throw new IllegalArgumentException("tenant authority evidence must use Ed25519");
        }
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    private static void require(Pattern pattern, String value, String field) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }
}
