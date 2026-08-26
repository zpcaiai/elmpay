package com.elmpay.money;

import java.util.Locale;
import java.util.Objects;

/** Version-bound currency metadata. Amounts are always expressed in minor units. */
public record CurrencyUnit(String code, int fractionDigits, String metadataVersion) {
    public CurrencyUnit {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(metadataVersion, "metadataVersion");
        code = code.toUpperCase(Locale.ROOT);
        if (!code.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency code must be ISO-4217 alpha-3");
        }
        if (fractionDigits < 0 || fractionDigits > 4) {
            throw new IllegalArgumentException("unsupported currency fraction digits");
        }
        if (metadataVersion.isBlank()) {
            throw new IllegalArgumentException("currency metadata version is required");
        }
    }
}
