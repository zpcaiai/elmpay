package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class WebhookProcessorRuntimeTest {
    private static final String TENANT_ONE = "00000000-0000-4000-8000-000000000001";
    private static final String TENANT_TWO = "00000000-0000-4000-8000-000000000002";

    @Test
    void runsOneBoundedFairTurnPerTenantAndIsolatesFailures() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T00:00:00Z"));
        AtomicReference<String> cursor = new AtomicReference<>();
        WebhookProcessorRuntime.TenantSource source = new WebhookProcessorRuntime.TenantSource() {
            @Override public void verifyRequiredSchema() { }
            @Override public List<String> claimableTenants(int maximum, String after,
                    Instant dueAt) {
                cursor.set(after);
                return List.of(TENANT_ONE, TENANT_TWO);
            }
        };
        WebhookProcessorRuntime runtime = new WebhookProcessorRuntime(
                WebhookProcessorSettingsTest.settings(Duration.ofSeconds(30),
                        Duration.ofSeconds(90)), clock, source,
                (tenant, worker) -> {
                    if (TENANT_TWO.equals(tenant)) {
                        throw new IllegalStateException("database detail must not enter health");
                    }
                    return WebhookInboxProcessor.Outcome.PROCESSED;
                });
        try {
            WebhookProcessorRuntime.CycleResult first = runtime.runCycle();
            assertEquals(2, first.tenants());
            assertEquals(1, first.processed());
            assertEquals(1, first.failures());
            assertFalse(first.successful());
            assertEquals(1, runtime.totalFailures());
            runtime.runCycle();
            assertEquals(TENANT_TWO, cursor.get());
        } finally {
            runtime.close();
        }
    }

    @Test
    void startupReadinessHealthAndGracefulCloseReflectRealSuccessfulCycle()
            throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T00:00:00Z"));
        AtomicInteger schemaChecks = new AtomicInteger();
        WebhookProcessorRuntime.TenantSource source = new WebhookProcessorRuntime.TenantSource() {
            @Override public void verifyRequiredSchema() { schemaChecks.incrementAndGet(); }
            @Override public List<String> claimableTenants(int maximum, String after,
                    Instant dueAt) { return List.of(); }
        };
        WebhookProcessorRuntime runtime = new WebhookProcessorRuntime(
                WebhookProcessorSettingsTest.settings(), clock, source,
                (tenant, worker) -> WebhookInboxProcessor.Outcome.IDLE);
        WebhookProcessorHealthServer health = new WebhookProcessorHealthServer(runtime,
                "127.0.0.1", 0);
        try {
            assertFalse(runtime.startupHealthy());
            runtime.start();
            health.start();
            for (int index = 0; index < 100 && !runtime.ready(); index++) {
                Thread.sleep(10);
            }
            assertEquals(1, schemaChecks.get());
            assertTrue(runtime.ready());
            assertProbe(health.port(), "/health/startup", 200);
            assertProbe(health.port(), "/health/live", 200);
            assertProbe(health.port(), "/health/ready", 200);
            clock.advance(Duration.ofSeconds(91));
            assertFalse(runtime.ready());
            assertProbe(health.port(), "/health/ready", 503);
            assertThrows(IllegalStateException.class, runtime::start);
        } finally {
            health.close();
            runtime.close();
        }
        assertFalse(runtime.live());
        assertThrows(IllegalStateException.class, runtime::runCycle);
    }

    private static void assertProbe(int port, String path, int status) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + port + path)).GET().build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(status, response.statusCode());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        assertFalse(response.body().contains(TENANT_ONE));
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> current;
        private MutableClock(Instant value) { current = new AtomicReference<>(value); }
        private void advance(Duration duration) { current.updateAndGet(value -> value.plus(duration)); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return current.get(); }
    }
}
