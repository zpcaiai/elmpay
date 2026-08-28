package com.elmpay.payment.checkout;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.util.Currency;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

/** Versioned checkout messages, RTL metadata and exact minor-unit display formatting. */
public final class CheckoutLocalization {
    private static final String DEFAULT_RESOURCE = "checkout/catalog-v1.properties";
    private final String catalogVersion;
    private final Map<String, Map<String, String>> messages;
    private final Map<String, Integer> currencyDigits;

    public CheckoutLocalization(String catalogVersion, Map<String, Map<String, String>> messages,
            Map<String, Integer> currencyDigits) {
        if (catalogVersion == null || catalogVersion.isBlank()) {
            throw new IllegalArgumentException("catalog version required");
        }
        if (messages == null || !messages.containsKey("en") || messages.get("en").isEmpty()) {
            throw new IllegalArgumentException("an English checkout catalog is required");
        }
        Map<String, Map<String, String>> catalogs = new LinkedHashMap<>();
        SetView expected = new SetView(messages.get("en"));
        messages.forEach((locale, catalog) -> {
            String tag = Locale.forLanguageTag(locale).toLanguageTag();
            if ("und".equals(tag) || catalog == null || catalog.isEmpty()
                    || !expected.matches(catalog)) {
                throw new IllegalArgumentException(
                        "checkout locale catalogs must have identical non-empty keys");
            }
            catalogs.put(tag, Map.copyOf(catalog));
        });
        Map<String, Integer> digits = new LinkedHashMap<>();
        if (currencyDigits == null || currencyDigits.isEmpty()) {
            throw new IllegalArgumentException("versioned currency metadata is required");
        }
        currencyDigits.forEach((code, scale) -> {
            String normalized = code.toUpperCase(Locale.ROOT);
            if (!normalized.matches("[A-Z]{3}") || scale == null || scale < 0 || scale > 3) {
                throw new IllegalArgumentException("currency metadata is invalid");
            }
            digits.put(normalized, scale);
        });
        this.catalogVersion = catalogVersion;
        this.messages = Map.copyOf(catalogs);
        this.currencyDigits = Map.copyOf(digits);
    }

    public static CheckoutLocalization defaultCatalog() {
        Properties properties = new Properties();
        ClassLoader loader = CheckoutLocalization.class.getClassLoader();
        try (var reader = new InputStreamReader(Objects.requireNonNull(
                loader.getResourceAsStream(DEFAULT_RESOURCE),
                "checkout localization resource is missing"), StandardCharsets.UTF_8)) {
            properties.load(reader);
        } catch (IOException failure) {
            throw new IllegalStateException("checkout localization catalog cannot be read",
                    failure);
        }
        String version = required(properties, "catalog.version");
        Map<String, Map<String, String>> localized = new LinkedHashMap<>();
        Map<String, Integer> digits = new LinkedHashMap<>();
        properties.stringPropertyNames().stream().sorted().forEach(name -> {
            if (name.startsWith("locale.")) {
                String remainder = name.substring("locale.".length());
                int separator = remainder.indexOf('.');
                if (separator < 1 || separator == remainder.length() - 1) {
                    throw new IllegalArgumentException("invalid checkout locale catalog key");
                }
                String locale = remainder.substring(0, separator);
                String key = remainder.substring(separator + 1);
                localized.computeIfAbsent(locale, ignored -> new LinkedHashMap<>())
                        .put(key, required(properties, name));
            } else if (name.startsWith("currency.") && name.endsWith(".digits")) {
                String code = name.substring("currency.".length(), name.length()
                        - ".digits".length());
                try {
                    digits.put(code, Integer.parseInt(required(properties, name)));
                } catch (NumberFormatException invalid) {
                    throw new IllegalArgumentException("invalid checkout currency metadata",
                            invalid);
                }
            }
        });
        return new CheckoutLocalization(version, localized, digits);
    }

    public String catalogVersion() {
        return catalogVersion;
    }

    public String localeTag(Locale requested) {
        return catalog(requested).tag();
    }

    public String direction(Locale requested) {
        String configured = catalog(requested).messages().get("direction");
        if (!"ltr".equals(configured) && !"rtl".equals(configured)) {
            throw new IllegalStateException("checkout locale direction is invalid");
        }
        return configured;
    }

    public String message(Locale requested, String key) {
        String value = catalog(requested).messages().get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("unknown message key");
        }
        return value;
    }

    public Map<String, String> browserMessages(Locale requested, String status) {
        Map<String, String> catalog = catalog(requested).messages();
        Map<String, String> result = new LinkedHashMap<>();
        catalog.forEach((key, value) -> {
            if (!"direction".equals(key) && (key.startsWith("ui.")
                    || key.startsWith("error."))) {
                result.put(key, value);
            }
        });
        result.put("status.current", message(requested, "status." + status));
        return Map.copyOf(result);
    }

    public String methodLabel(Locale requested, String method) {
        String key = "method." + method.toLowerCase(Locale.ROOT);
        String value = catalog(requested).messages().get(key);
        return value == null ? method.replace('_', ' ') : value;
    }

    public String formatMoney(long minor, String currencyCode, Locale locale) {
        String normalized = currencyCode.toUpperCase(Locale.ROOT);
        Integer digits = currencyDigits.get(normalized);
        if (digits == null) {
            throw new IllegalArgumentException("currency metadata is not versioned");
        }
        BigDecimal major = BigDecimal.valueOf(minor, digits);
        NumberFormat formatter = NumberFormat.getCurrencyInstance(locale);
        formatter.setCurrency(Currency.getInstance(normalized));
        formatter.setMinimumFractionDigits(digits);
        formatter.setMaximumFractionDigits(digits);
        return formatter.format(major);
    }

    private Catalog catalog(Locale requested) {
        Objects.requireNonNull(requested, "requested");
        String exact = requested.toLanguageTag();
        Map<String, String> value = messages.get(exact);
        if (value != null) {
            return new Catalog(exact, value);
        }
        String language = requested.getLanguage();
        value = messages.get(language);
        if (value != null) {
            return new Catalog(language, value);
        }
        return new Catalog("en", messages.get("en"));
    }

    private static String required(Properties properties, String key) {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("checkout catalog value is missing: " + key);
        }
        return value;
    }

    private record Catalog(String tag, Map<String, String> messages) {}

    private record SetView(java.util.Set<String> keys) {
        SetView(Map<String, String> values) {
            this(values.keySet());
            if (values.values().stream().anyMatch(value -> value == null || value.isBlank())) {
                throw new IllegalArgumentException("checkout catalog values must not be blank");
            }
        }

        boolean matches(Map<String, String> values) {
            return keys.equals(values.keySet())
                    && values.values().stream().noneMatch(value -> value == null
                            || value.isBlank());
        }
    }
}
