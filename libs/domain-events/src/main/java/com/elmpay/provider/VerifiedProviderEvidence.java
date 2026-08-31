package com.elmpay.provider;

import java.util.Map;

/** Opaque result that can only be created by {@link ProviderEvidenceVerifier}. */
public final class VerifiedProviderEvidence {
    private final String evidenceType;
    private final Map<String, String> fields;
    private final String receiptDigest;
    private final String signerIdentity;

    VerifiedProviderEvidence(String evidenceType, Map<String, String> fields,
            String receiptDigest, String signerIdentity) {
        this.evidenceType = evidenceType;
        this.fields = Map.copyOf(fields);
        this.receiptDigest = receiptDigest;
        this.signerIdentity = signerIdentity;
    }

    public String evidenceType() {
        return evidenceType;
    }

    public Map<String, String> fields() {
        return fields;
    }

    public String receiptDigest() {
        return receiptDigest;
    }

    public String signerIdentity() {
        return signerIdentity;
    }
}
