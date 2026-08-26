package com.elmpay.observability;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;

final class RedactorTest {
    @Test
    void minimizesPersonalAndCredentialFields() {
        Map<String, Object> output = Redactor.safeFields(Map.of(
                "email", "person@example.test", "authorization", "secret", "status", "ok"));
        assertEquals("[MINIMIZED]", output.get("email"));
        assertEquals("[REDACTED]", output.get("authorization"));
        assertEquals("ok", output.get("status"));
    }
}
