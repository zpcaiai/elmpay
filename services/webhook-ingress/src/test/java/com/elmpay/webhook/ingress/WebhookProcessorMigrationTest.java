package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class WebhookProcessorMigrationTest {
    @Test
    void tenantDiscoveryIsBoundedSecurityDefinerAndPublicAccessIsRevoked()
            throws IOException {
        String sql = resource("db/migration/V037_2__provider_webhook_processor_runtime.sql");
        assertTrue(sql.contains("SECURITY DEFINER"));
        assertTrue(sql.contains("SET row_security = off"));
        assertTrue(sql.contains("maximum_tenants < 1 OR maximum_tenants > 1000"));
        assertTrue(sql.contains("terminal_failure = FALSE"));
        assertTrue(sql.contains("lease_expires_at <= due_at"));
        assertTrue(sql.contains("REVOKE ALL ON FUNCTION"));
        assertTrue(sql.contains("TO elmpay_webhook_processor"));
        assertFalse(sql.contains("raw_body"));
    }

    private static String resource(String name) throws IOException {
        try (var input = WebhookProcessorMigrationTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            assertNotNull(input, name);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
