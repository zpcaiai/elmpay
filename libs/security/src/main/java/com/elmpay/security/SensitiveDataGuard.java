package com.elmpay.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Rejects cardholder data and common credentials before persistence or logging. */
public final class SensitiveDataGuard {
    // The list itself lives in governance/payment-method.json and reaches Java through the
    // generated SensitiveFieldCatalog. A literal copy here is what let `card_pan` walk past a
    // guard that was watching `pan` (B35).
    private static final Pattern DIGITS = Pattern.compile("(?<!\\d)(?:\\d[ -]?){13,19}(?!\\d)");

    private SensitiveDataGuard() {
    }

    public static void assertSafe(Map<String, ?> fields) {
        inspect(fields, "$");
    }

    public static Map<String, Object> redact(Map<String, ?> fields) {
        Map<String, Object> redacted = new LinkedHashMap<>();
        fields.forEach((key, value) -> redacted.put(key,
                isDeniedKey(key) ? "[REDACTED]" : redactValue(value)));
        return Collections.unmodifiableMap(redacted);
    }

    private static void inspect(Object value, String path) {
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                if (isDeniedKey(key)) {
                    throw new IllegalArgumentException("sensitive field is forbidden: " + path + "." + key);
                }
                inspect(entry.getValue(), path + "." + key);
            }
        } else if (value instanceof Collection<?> collection) {
            int index = 0;
            for (Object item : collection) {
                inspect(item, path + "[" + index + "]");
                index++;
            }
        } else if (value instanceof CharSequence text && containsPaymentCard(text.toString())) {
            throw new IllegalArgumentException("possible primary account number is forbidden at " + path);
        }
    }

    private static Object redactValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> nested = new LinkedHashMap<>();
            map.forEach((key, nestedValue) -> nested.put(String.valueOf(key),
                    isDeniedKey(String.valueOf(key)) ? "[REDACTED]" : redactValue(nestedValue)));
            return Collections.unmodifiableMap(nested);
        }
        if (value instanceof Collection<?> collection) {
            List<Object> nested = new ArrayList<>();
            collection.forEach(item -> nested.add(redactValue(item)));
            return List.copyOf(nested);
        }
        if (value instanceof CharSequence text && containsPaymentCard(text.toString())) {
            return "[REDACTED]";
        }
        return value;
    }

    private static boolean isDeniedKey(String key) {
        return SensitiveFieldCatalog.denied(key);
    }

    private static boolean containsPaymentCard(String value) {
        Matcher matcher = DIGITS.matcher(value);
        while (matcher.find()) {
            String candidate = matcher.group().replace(" ", "").replace("-", "");
            if (candidate.length() >= 13 && candidate.length() <= 19 && passesLuhn(candidate)) {
                return true;
            }
        }
        return false;
    }

    private static boolean passesLuhn(String digits) {
        int sum = 0;
        boolean doubled = false;
        for (int index = digits.length() - 1; index >= 0; index--) {
            int digit = digits.charAt(index) - '0';
            if (doubled) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubled = !doubled;
        }
        return sum % 10 == 0;
    }
}
