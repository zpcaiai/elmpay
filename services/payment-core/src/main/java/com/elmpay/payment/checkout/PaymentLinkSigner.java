package com.elmpay.payment.checkout;

/** KMS/HSM boundary for B57 short-lived payment-link signatures. */
public interface PaymentLinkSigner {
    record Signature(String keyVersion, String value) {
        public Signature {
            if (keyVersion == null || keyVersion.isBlank() || value == null || value.isBlank()) {
                throw new IllegalArgumentException("signature key version and value are required");
            }
        }
    }

    Signature sign(byte[] canonicalPayload);

    /** Current enabled KMS MAC-key version. Signatures must be deterministic MAC values. */
    String activeKeyVersion();

    boolean verify(String keyVersion, byte[] canonicalPayload, String signature);

    boolean ready();
}
