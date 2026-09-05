package com.elmpay.payment;

import com.elmpay.security.SensitiveDataGuard;
import com.elmpay.security.SensitiveFieldCatalog;
import java.net.URI;
import java.util.Objects;

/** Non-sensitive reference to a token held by a PCI-scoped PSP or wallet provider. */
public record PaymentMethodReference(String method, URI reference, String fingerprint) {
    private static final int MAX_REFERENCE_LENGTH = 512;

    public PaymentMethodReference {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(reference, "reference");
        Objects.requireNonNull(fingerprint, "fingerprint");
        if (method.isBlank() || fingerprint.isBlank() || fingerprint.length() > 128
                || reference.toString().length() > MAX_REFERENCE_LENGTH
                || !SensitiveFieldCatalog.TOKEN_SCHEMES.contains(
                        String.valueOf(reference.getScheme()))
                || reference.getRawAuthority() == null
                || reference.getRawAuthority().isBlank()
                || reference.getSchemeSpecificPart() == null
                || reference.getSchemeSpecificPart().isBlank()) {
            throw new IllegalArgumentException("payment method must be an external token reference");
        }
        SensitiveDataGuard.assertSafe(java.util.Map.of(
                "payment_method", method, "reference", reference.toString(),
                "fingerprint", fingerprint));
    }

    public static PaymentMethodReference parse(String method, String reference, String fingerprint) {
        return new PaymentMethodReference(method, URI.create(reference), fingerprint);
    }
}
