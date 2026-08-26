package com.elmpay.payment.checkout;

import java.math.BigDecimal;
import java.text.NumberFormat;
import java.util.Currency;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Versioned checkout messages and exact minor-unit display formatting. */
public final class CheckoutLocalization {
    private final String catalogVersion;
    private final Map<String, Map<String, String>> messages;
    private final Map<String, Integer> currencyDigits;

    public CheckoutLocalization(String catalogVersion, Map<String, Map<String, String>> messages,
                                Map<String, Integer> currencyDigits) {
        if (catalogVersion == null || catalogVersion.isBlank()) throw new IllegalArgumentException("catalog version required");
        this.catalogVersion = catalogVersion;
        this.messages = Map.copyOf(messages);
        this.currencyDigits = Map.copyOf(currencyDigits);
    }

    public String catalogVersion() { return catalogVersion; }

    public String message(Locale requested, String key) {
        Objects.requireNonNull(requested, "requested");
        Map<String, String> catalog = messages.getOrDefault(requested.toLanguageTag(), messages.get("en"));
        if (catalog == null || !catalog.containsKey(key)) throw new IllegalArgumentException("unknown message key");
        return catalog.get(key);
    }

    public String formatMoney(long minor, String currencyCode, Locale locale) {
        Integer digits = currencyDigits.get(currencyCode);
        if (digits == null) throw new IllegalArgumentException("currency metadata is not versioned");
        BigDecimal major = BigDecimal.valueOf(minor, digits);
        NumberFormat formatter = NumberFormat.getCurrencyInstance(locale);
        formatter.setCurrency(Currency.getInstance(currencyCode));
        formatter.setMinimumFractionDigits(digits);
        formatter.setMaximumFractionDigits(digits);
        return formatter.format(major);
    }
}
