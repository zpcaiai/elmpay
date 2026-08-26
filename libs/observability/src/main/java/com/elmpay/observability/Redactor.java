package com.elmpay.observability;

import com.elmpay.security.SensitiveDataGuard;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Central logging redactor. Callers log this result, never raw request objects. */
public final class Redactor {
    private static final Set<String> PERSONAL = Set.of("name", "email", "phone", "address",
            "ip", "openid", "identity_document", "device_id", "payment_token");

    private Redactor() {
    }

    public static Map<String, Object> safeFields(Map<String, ?> fields) {
        Map<String, Object> firstPass = SensitiveDataGuard.redact(fields);
        Map<String, Object> result = new LinkedHashMap<>();
        firstPass.forEach((key, value) -> result.put(key,
                PERSONAL.contains(key.toLowerCase(Locale.ROOT)) ? "[MINIMIZED]" : value));
        return Map.copyOf(result);
    }
}
