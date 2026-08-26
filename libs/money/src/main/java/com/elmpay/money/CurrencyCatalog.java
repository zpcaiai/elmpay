package com.elmpay.money;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Controlled currency metadata; changes are reviewed and versioned with the code. */
public final class CurrencyCatalog {
    public static final String VERSION = "iso4217-2026-01";

    private static final Map<String, Integer> FRACTIONS = Map.ofEntries(
            Map.entry("AUD", 2), Map.entry("CAD", 2), Map.entry("CHF", 2),
            Map.entry("CNY", 2), Map.entry("EUR", 2), Map.entry("GBP", 2),
            Map.entry("HKD", 2), Map.entry("JPY", 0), Map.entry("KRW", 0),
            Map.entry("SGD", 2), Map.entry("USD", 2));

    private CurrencyCatalog() {
    }

    public static CurrencyUnit require(String code) {
        Objects.requireNonNull(code, "code");
        String normalized = code.toUpperCase(Locale.ROOT);
        Integer fractionDigits = FRACTIONS.get(normalized);
        if (fractionDigits == null) {
            throw new IllegalArgumentException("currency is not enabled: " + normalized);
        }
        return new CurrencyUnit(normalized, fractionDigits, VERSION);
    }

    public static boolean isEnabled(String code) {
        return code != null && FRACTIONS.containsKey(code.toUpperCase(Locale.ROOT));
    }
}
