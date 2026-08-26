package com.elmpay.payment;

import com.elmpay.security.SensitiveDataGuard;
import java.net.URI;
import java.util.Objects;
import java.util.Set;

/** Non-sensitive reference to a token held by a PCI-scoped PSP or wallet provider. */
public record PaymentMethodReference(String method, URI reference, String fingerprint) {
    private static final Set<String> SAFE_SCHEMES = Set.of("psp", "wallet", "mandate");

    public PaymentMethodReference {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(reference, "reference");
        Objects.requireNonNull(fingerprint, "fingerprint");
        if (method.isBlank() || fingerprint.isBlank() || fingerprint.length() > 128
                || !SAFE_SCHEMES.contains(reference.getScheme())
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
