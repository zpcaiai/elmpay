package com.elmpay.reconciliation;

/**
 * KMS/HSM boundary for financial exports. Implementations must keep key material outside the JVM
 * and route verification by the immutable key version recorded in each report.
 */
public interface ExportManifestSigner {
    record Signature(String keyVersion, String value) {
        public Signature {
            if (keyVersion == null || keyVersion.isBlank() || value == null || value.isBlank()) {
                throw new IllegalArgumentException("signature key version and value are required");
            }
        }
    }

    /** Returns only after the remote signer has authenticated this exact canonical manifest. */
    Signature sign(byte[] canonicalManifest);

    /** Verifies with the named historical key version; unknown/revoked versions fail closed. */
    boolean verify(String keyVersion, byte[] canonicalManifest, String signature);

    /** Includes remote reachability, authorization and an enabled signing-key version. */
    boolean ready();
}
