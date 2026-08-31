package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class WebhookProcessorSettingsTest {
    @Test
    void parsesBoundedMountedTlsProductionContract() {
        WebhookProcessorSettings settings = WebhookProcessorSettings.from(environment());
        assertEquals("webhook-processor-0", settings.processorId());
        assertEquals(Duration.ofSeconds(30), settings.leaseTtl());
        assertEquals(100, settings.maximumTenantsPerCycle());
        assertEquals(8, settings.maximumAttempts());
    }

    @Test
    void rejectsInlineCredentialOrTlsOverrideAndSharedFixedIdentity() {
        Map<String, String> inline = environment();
        inline.put("ELMPAY_DATABASE_URL",
                "jdbc:postgresql://postgres:5432/elmpay?sslmode=disable");
        assertThrows(IllegalArgumentException.class,
                () -> WebhookProcessorSettings.from(inline));

        Map<String, String> missingDownwardIdentity = environment();
        missingDownwardIdentity.remove("ELMPAY_WEBHOOK_PROCESSOR_ID");
        assertThrows(IllegalStateException.class,
                () -> WebhookProcessorSettings.from(missingDownwardIdentity));
    }

    static WebhookProcessorSettings settings() {
        return WebhookProcessorSettings.from(environment());
    }

    static WebhookProcessorSettings settings(Duration poll, Duration readiness) {
        Map<String, String> values = environment();
        values.put("ELMPAY_WEBHOOK_PROCESSOR_POLL_INTERVAL", poll.toString());
        values.put("ELMPAY_WEBHOOK_PROCESSOR_READINESS_MAX_STALENESS", readiness.toString());
        return WebhookProcessorSettings.from(values);
    }

    private static Map<String, String> environment() {
        Map<String, String> values = new HashMap<>();
        values.put("ELMPAY_WEBHOOK_PROCESSOR_ID", "webhook-processor-0");
        values.put("ELMPAY_DATABASE_URL", "jdbc:postgresql://postgres:5432/elmpay");
        values.put("ELMPAY_DATABASE_USERNAME", "elmpay_webhook_processor");
        values.put("ELMPAY_DATABASE_PASSWORD_FILE", Path.of("/var/run/secrets/elmpay-db/password").toString());
        values.put("ELMPAY_DATABASE_CA_FILE", Path.of("/var/run/secrets/elmpay-db/ca.crt").toString());
        values.put("ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE", Path.of("/var/run/secrets/elmpay-db/tls.crt").toString());
        values.put("ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE", Path.of("/var/run/secrets/elmpay-db/tls.key").toString());
        values.put("ELMPAY_WEBHOOK_PROCESSOR_POLL_INTERVAL", "PT1S");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_READINESS_MAX_STALENESS", "PT10S");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_MAX_TENANTS", "100");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_LEASE_TTL", "PT30S");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_BASE_BACKOFF", "PT2S");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_MAX_BACKOFF", "PT5M");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_MAX_ATTEMPTS", "8");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_HEALTH_HOST", "0.0.0.0");
        values.put("ELMPAY_WEBHOOK_PROCESSOR_HEALTH_PORT", "8081");
        return values;
    }
}
