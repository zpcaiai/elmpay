package com.elmpay.observability;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class TelemetryContextTest {
    private static final UUID TENANT = UUID.fromString("e29381c8-7cca-45d0-8bd3-789b130f2ce4");
    private static final UUID PROJECT = UUID.fromString("e168a3dd-cf29-4189-b16d-dc47097d4711");

    @Test
    void retainsCorrelationIdentityAndDefensivelyCopiesAttributes() {
        Map<String, String> input = new HashMap<>(Map.of("provider", "local-sandbox"));
        TelemetryContext context = new TelemetryContext("trace-1", "correlation-2", TENANT,
                PROJECT, "payment.status", input);
        input.put("provider", "changed-after-construction");
        input.put("unexpected", "value");
        assertEquals("trace-1", context.traceId());
        assertEquals("correlation-2", context.correlationId());
        assertEquals(TENANT, context.tenantId());
        assertEquals(PROJECT, context.projectId());
        assertEquals("payment.status", context.operation());
        assertEquals(Map.of("provider", "local-sandbox"), context.attributes());
        assertThrows(UnsupportedOperationException.class,
                () -> context.attributes().put("provider", "mutated"));
    }

    @Test
    void allowsTenantWideContextWithoutAProject() {
        TelemetryContext context = new TelemetryContext("trace", "correlation", TENANT,
                null, "tenant.status", Map.of());
        assertNull(context.projectId());
        assertEquals(Map.of(), context.attributes());
    }

    @Test
    void rejectsEachMissingRequiredComponent() {
        assertThrows(NullPointerException.class,
                () -> new TelemetryContext(null, "correlation", TENANT, PROJECT, "status", Map.of()));
        assertThrows(NullPointerException.class,
                () -> new TelemetryContext("trace", null, TENANT, PROJECT, "status", Map.of()));
        assertThrows(NullPointerException.class,
                () -> new TelemetryContext("trace", "correlation", null, PROJECT, "status", Map.of()));
        assertThrows(NullPointerException.class,
                () -> new TelemetryContext("trace", "correlation", TENANT, PROJECT, null, Map.of()));
        assertThrows(NullPointerException.class,
                () -> new TelemetryContext("trace", "correlation", TENANT, PROJECT, "status", null));
    }

    @Test
    void rejectsBlankTraceCorrelationAndOperationIndependently() {
        for (String blank : new String[] {"", " ", "\t\n"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new TelemetryContext(blank, "correlation", TENANT, PROJECT, "status", Map.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> new TelemetryContext("trace", blank, TENANT, PROJECT, "status", Map.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> new TelemetryContext("trace", "correlation", TENANT, PROJECT, blank, Map.of()));
        }
    }

    @Test
    void rejectsNullAttributeKeysAndValues() {
        Map<String, String> missingKey = new HashMap<>();
        missingKey.put(null, "value");
        assertThrows(NullPointerException.class, () -> new TelemetryContext("trace", "correlation",
                TENANT, PROJECT, "status", missingKey));
        Map<String, String> missingValue = new HashMap<>();
        missingValue.put("provider", null);
        assertThrows(NullPointerException.class, () -> new TelemetryContext("trace", "correlation",
                TENANT, PROJECT, "status", missingValue));
    }
}
