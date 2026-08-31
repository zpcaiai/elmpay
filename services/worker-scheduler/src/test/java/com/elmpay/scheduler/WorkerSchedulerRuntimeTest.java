package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.scheduler.JdbcWorkerScopeRegistry.Scope;
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
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class WorkerSchedulerRuntimeTest {
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT_ONE =
            UUID.fromString("00000000-0000-0000-0000-000000000011");
    private static final UUID PROJECT_TWO =
            UUID.fromString("00000000-0000-0000-0000-000000000012");

    @Test
    void executesEachTenantOnceEachProjectOnceAndPartitionOncePerDay() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T01:00:00Z"));
        AtomicInteger partitions = new AtomicInteger();
        WorkerSchedulerRuntime runtime = runtime(clock, scopes(),
                (tenant, now) -> new int[] {2, 1},
                (tenant, now) -> new BillingLifecycleJob.Result(3, 4),
                scope -> 5, partitions::incrementAndGet);
        try {
            WorkerSchedulerRuntime.CycleResult first = runtime.runCycle();
            assertEquals(2, first.scopes());
            assertEquals(1, first.tenants());
            assertEquals(2, first.publishedEvents());
            assertEquals(1, first.retryScheduledEvents());
            assertEquals(10, first.projectedEvents());
            assertEquals(3, first.renewalEvents());
            assertEquals(4, first.dunningEvents());
            assertTrue(first.partitionMaintenanceRan());
            assertTrue(first.successful());
            assertEquals(clock.instant(), runtime.lastSuccessfulCycle());

            WorkerSchedulerRuntime.CycleResult second = runtime.runCycle();
            assertFalse(second.partitionMaintenanceRan());
            assertEquals(1, partitions.get());
            clock.advance(Duration.ofDays(1));
            assertTrue(runtime.runCycle().partitionMaintenanceRan());
            assertEquals(2, partitions.get());
        } finally {
            runtime.close();
        }
    }

    @Test
    void isolatesEveryStageFailureAndDoesNotClaimReadiness() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T01:00:00Z"));
        WorkerSchedulerRuntime runtime = runtime(clock, scopes(),
                (tenant, now) -> { throw new IllegalStateException("secret database detail"); },
                (tenant, now) -> { throw new IllegalStateException("billing"); },
                scope -> { throw new IllegalStateException("projection"); },
                () -> { throw new IllegalStateException("partition"); });
        try {
            WorkerSchedulerRuntime.CycleResult result = runtime.runCycle();
            assertEquals(5, result.failures());
            assertFalse(result.successful());
            assertEquals(5, runtime.totalFailures());
            assertEquals(clock.instant(), runtime.lastCompletedCycle());
            assertNull(runtime.lastSuccessfulCycle());
            assertFalse(runtime.ready());
        } finally {
            runtime.close();
        }
    }

    @Test
    void lifecycleAndHealthProbesReflectRealCycleFreshness() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T01:00:00Z"));
        AtomicInteger schemaChecks = new AtomicInteger();
        WorkerSchedulerRuntime.ScopeSource source = new WorkerSchedulerRuntime.ScopeSource() {
            @Override
            public void verifyRequiredSchema() {
                schemaChecks.incrementAndGet();
            }

            @Override
            public List<Scope> activeScopes(int maximum, Scope after) {
                return List.of();
            }
        };
        WorkerSchedulerRuntime runtime = new WorkerSchedulerRuntime(
                WorkerSchedulerSettingsTest.settings(), clock, source,
                (tenant, now) -> new int[] {0, 0},
                (tenant, now) -> new BillingLifecycleJob.Result(0, 0), scope -> 0, () -> {});
        WorkerHealthServer health = new WorkerHealthServer(runtime, "127.0.0.1", 0);
        try {
            assertFalse(runtime.startupHealthy());
            runtime.start();
            health.start();
            awaitReady(runtime);
            assertEquals(1, schemaChecks.get());
            assertTrue(runtime.startupHealthy());
            assertTrue(runtime.live());
            assertTrue(runtime.ready());
            assertProbe(health.port(), "/health/startup", 200, "startup");
            assertProbe(health.port(), "/health/live", 200, "live");
            assertProbe(health.port(), "/health/ready", 200, "ready");
            assertMethodRejected(health.port());

            clock.advance(Duration.ofMinutes(1));
            assertFalse(runtime.ready());
            assertProbe(health.port(), "/health/ready", 503, "unavailable");
            assertThrows(IllegalStateException.class, runtime::start);
        } finally {
            health.close();
            runtime.close();
        }
        assertFalse(runtime.live());
        assertFalse(runtime.startupHealthy());
        runtime.close();
        assertThrows(IllegalStateException.class, runtime::runCycle);
    }

    @Test
    void concurrentCycleIsRejectedInsteadOfOverlappingSideEffects() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T01:00:00Z"));
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        WorkerSchedulerRuntime runtime = runtime(clock, List.of(new Scope(TENANT, PROJECT_ONE)),
                (tenant, now) -> {
                    entered.countDown();
                    await(release);
                    return new int[] {0, 0};
                }, (tenant, now) -> new BillingLifecycleJob.Result(0, 0), scope -> 0, () -> {});
        AtomicReference<Throwable> backgroundFailure = new AtomicReference<>();
        Thread background = new Thread(() -> {
            try {
                runtime.runCycle();
            } catch (Throwable failure) {
                backgroundFailure.set(failure);
            }
        });
        background.start();
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        assertThrows(IllegalStateException.class, runtime::runCycle);
        release.countDown();
        background.join(2_000);
        assertFalse(background.isAlive());
        assertNull(backgroundFailure.get());
        runtime.close();
    }

    @Test
    void cycleResultRejectsImpossibleCounters() {
        assertThrows(IllegalArgumentException.class, () -> new WorkerSchedulerRuntime.CycleResult(
                -1, 0, 0, 0, 0, 0, 0, false, 0));
    }

    @Test
    void rolloutAdminPollingIsBoundedRunsWithoutTenantScopesAndFailsReadinessClosed() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T01:00:00Z"));
        AtomicInteger calls = new AtomicInteger();
        WorkerSchedulerRuntime runtime = runtime(clock, List.of(),
                (tenant, now) -> new int[] {0, 0},
                (tenant, now) -> new BillingLifecycleJob.Result(0, 0), scope -> 0, () -> {},
                () -> calls.incrementAndGet() <= 2);
        try {
            WorkerSchedulerRuntime.CycleResult result = runtime.runCycle();
            assertEquals(2, result.rolloutAdminCommands());
            assertEquals(3, calls.get());
            assertTrue(result.successful());
        } finally {
            runtime.close();
        }

        WorkerSchedulerRuntime failed = runtime(clock, List.of(),
                (tenant, now) -> new int[] {0, 0},
                (tenant, now) -> new BillingLifecycleJob.Result(0, 0), scope -> 0, () -> {},
                () -> { throw new IllegalStateException("database detail"); });
        try {
            assertEquals(1, failed.runCycle().failures());
            assertNull(failed.lastSuccessfulCycle());
        } finally {
            failed.close();
        }
    }

    @Test
    void auxiliaryProductionWorkRunsOncePerTenantAndItsFailuresFailTheCycleClosed() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-30T01:00:00Z"));
        AtomicInteger auditCalls = new AtomicInteger();
        AtomicInteger webhookCalls = new AtomicInteger();
        WorkerSchedulerRuntime.ScopeSource source = new WorkerSchedulerRuntime.ScopeSource() {
            @Override
            public void verifyRequiredSchema() { }

            @Override
            public List<Scope> activeScopes(int maximum, Scope after) {
                return scopes();
            }
        };
        WorkerSchedulerRuntime runtime = new WorkerSchedulerRuntime(
                WorkerSchedulerSettingsTest.settings(), clock, source,
                (tenant, now) -> new int[] {0, 0},
                (tenant, now) -> new BillingLifecycleJob.Result(0, 0), scope -> 0, () -> { },
                () -> false,
                tenant -> auditCalls.incrementAndGet(),
                tenant -> {
                    webhookCalls.incrementAndGet();
                    throw new IllegalStateException("sensitive upstream failure");
                });
        try {
            WorkerSchedulerRuntime.CycleResult result = runtime.runCycle();
            assertEquals(1, auditCalls.get());
            assertEquals(1, webhookCalls.get());
            assertEquals(1, result.failures());
            assertFalse(result.successful());
            assertNull(runtime.lastSuccessfulCycle());
        } finally {
            runtime.close();
        }
    }

    private static WorkerSchedulerRuntime runtime(MutableClock clock, List<Scope> scopes,
            WorkerSchedulerRuntime.TenantOutboxWork outbox,
            WorkerSchedulerRuntime.TenantBillingWork billing,
            WorkerSchedulerRuntime.ProjectTimelineWork timeline,
            WorkerSchedulerRuntime.PartitionWork partition) {
        WorkerSchedulerRuntime.ScopeSource source = new WorkerSchedulerRuntime.ScopeSource() {
            @Override
            public void verifyRequiredSchema() {
            }

            @Override
            public List<Scope> activeScopes(int maximum, Scope after) {
                return scopes;
            }
        };
        return new WorkerSchedulerRuntime(WorkerSchedulerSettingsTest.settings(), clock, source,
                outbox, billing, timeline, partition);
    }

    private static WorkerSchedulerRuntime runtime(MutableClock clock, List<Scope> scopes,
            WorkerSchedulerRuntime.TenantOutboxWork outbox,
            WorkerSchedulerRuntime.TenantBillingWork billing,
            WorkerSchedulerRuntime.ProjectTimelineWork timeline,
            WorkerSchedulerRuntime.PartitionWork partition,
            WorkerSchedulerRuntime.AdminCommandWork admin) {
        WorkerSchedulerRuntime.ScopeSource source = new WorkerSchedulerRuntime.ScopeSource() {
            @Override
            public void verifyRequiredSchema() { }

            @Override
            public List<Scope> activeScopes(int maximum, Scope after) {
                return scopes;
            }
        };
        return new WorkerSchedulerRuntime(WorkerSchedulerSettingsTest.settings(), clock, source,
                outbox, billing, timeline, partition, admin);
    }

    private static List<Scope> scopes() {
        return List.of(new Scope(TENANT, PROJECT_ONE), new Scope(TENANT, PROJECT_TWO));
    }

    private static void awaitReady(WorkerSchedulerRuntime runtime) throws InterruptedException {
        for (int attempt = 0; attempt < 100 && !runtime.ready(); attempt++) {
            Thread.sleep(10);
        }
        assertTrue(runtime.ready());
        assertNotNull(runtime.lastResult());
    }

    private static void assertProbe(int port, String path, int status, String fragment)
            throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .GET().build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(status, response.statusCode());
        assertTrue(response.body().contains(fragment));
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
    }

    private static void assertMethodRejected(int port) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + port + "/health/live"))
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(405, response.statusCode());
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("test latch timed out");
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(failure);
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> current;

        private MutableClock(Instant instant) {
            this.current = new AtomicReference<>(instant);
        }

        void advance(Duration duration) {
            current.updateAndGet(value -> value.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("test clock supports UTC only");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return current.get();
        }
    }
}
