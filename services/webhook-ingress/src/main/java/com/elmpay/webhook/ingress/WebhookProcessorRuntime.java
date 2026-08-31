package com.elmpay.webhook.ingress;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;

/** Long-running, fairness-bounded verified provider webhook processor. */
public final class WebhookProcessorRuntime implements AutoCloseable {
    interface TenantSource {
        void verifyRequiredSchema();

        List<String> claimableTenants(int maximum, String afterTenant, Instant dueAt);
    }

    @FunctionalInterface
    interface TenantWork {
        WebhookInboxProcessor.Outcome run(String tenantId, String processorId);
    }

    public record CycleResult(int tenants, int processed, int duplicateEffects,
            int terminalFailures, int retriesScheduled, int leasesLost, int failures) {
        public CycleResult {
            if (tenants < 0 || processed < 0 || duplicateEffects < 0 || terminalFailures < 0
                    || retriesScheduled < 0 || leasesLost < 0 || failures < 0) {
                throw new IllegalArgumentException("cycle counters cannot be negative");
            }
        }

        public boolean successful() {
            return failures == 0;
        }
    }

    private final WebhookProcessorSettings settings;
    private final TenantSource tenantSource;
    private final TenantWork tenantWork;
    private final Clock clock;
    private final ScheduledExecutorService executor;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean cycleRunning = new AtomicBoolean();
    private final AtomicReference<String> tenantCursor = new AtomicReference<>();
    private final AtomicReference<Instant> lastSuccessfulCycle = new AtomicReference<>();
    private final AtomicReference<CycleResult> lastResult = new AtomicReference<>();
    private final AtomicLong totalFailures = new AtomicLong();

    public WebhookProcessorRuntime(WebhookProcessorSettings settings, DataSource dataSource,
            WebhookEffectPort effectPort, Clock clock) {
        this.settings = Objects.requireNonNull(settings, "settings");
        Objects.requireNonNull(dataSource, "dataSource");
        Objects.requireNonNull(effectPort, "effectPort");
        this.clock = Objects.requireNonNull(clock, "clock");
        JdbcWebhookTenantRegistry registry = new JdbcWebhookTenantRegistry(dataSource);
        this.tenantSource = new TenantSource() {
            @Override
            public void verifyRequiredSchema() {
                registry.verifyRequiredSchema();
            }

            @Override
            public List<String> claimableTenants(int maximum, String afterTenant, Instant dueAt) {
                return registry.claimableTenants(maximum, afterTenant, dueAt);
            }
        };
        WebhookInboxProcessor processor = new WebhookInboxProcessor(dataSource, effectPort, clock,
                settings.processingPolicy());
        this.tenantWork = processor::runOnce;
        this.executor = newExecutor();
    }

    WebhookProcessorRuntime(WebhookProcessorSettings settings, Clock clock,
            TenantSource tenantSource, TenantWork tenantWork) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tenantSource = Objects.requireNonNull(tenantSource, "tenantSource");
        this.tenantWork = Objects.requireNonNull(tenantWork, "tenantWork");
        this.executor = newExecutor();
    }

    private ScheduledExecutorService newExecutor() {
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "elmpay-webhook-processor-cycle");
            thread.setDaemon(false);
            thread.setUncaughtExceptionHandler((ignored, failure) -> totalFailures.incrementAndGet());
            return thread;
        };
        return Executors.newSingleThreadScheduledExecutor(factory);
    }

    public synchronized void start() {
        if (started.get()) {
            throw new IllegalStateException("webhook processor is already started");
        }
        if (closed.get()) {
            throw new IllegalStateException("closed webhook processor cannot start");
        }
        tenantSource.verifyRequiredSchema();
        started.set(true);
        try {
            executor.scheduleWithFixedDelay(this::runCycleSafely, 0,
                    settings.pollInterval().toMillis(), TimeUnit.MILLISECONDS);
        } catch (RuntimeException failure) {
            started.set(false);
            throw failure;
        }
    }

    public CycleResult runCycle() {
        if (closed.get()) {
            throw new IllegalStateException("webhook processor is closed");
        }
        if (!cycleRunning.compareAndSet(false, true)) {
            throw new IllegalStateException("a webhook processor cycle is already running");
        }
        try {
            Instant now = clock.instant();
            List<String> tenants = tenantSource.claimableTenants(
                    settings.maximumTenantsPerCycle(), tenantCursor.get(), now);
            tenantCursor.set(tenants.isEmpty() ? null : tenants.getLast());
            int processed = 0;
            int duplicates = 0;
            int terminal = 0;
            int retries = 0;
            int leases = 0;
            int failures = 0;
            for (String tenant : tenants) {
                try {
                    WebhookInboxProcessor.Outcome outcome = tenantWork.run(tenant,
                            settings.processorId());
                    switch (outcome) {
                        case PROCESSED -> processed++;
                        case DUPLICATE_EFFECT -> duplicates++;
                        case TERMINAL_FAILURE -> terminal++;
                        case RETRY_SCHEDULED -> retries++;
                        case LEASE_LOST -> leases++;
                        case IDLE -> { }
                    }
                } catch (RuntimeException failure) {
                    failures++;
                    totalFailures.incrementAndGet();
                }
            }
            CycleResult result = new CycleResult(tenants.size(), processed, duplicates, terminal,
                    retries, leases, failures);
            lastResult.set(result);
            if (result.successful()) {
                lastSuccessfulCycle.set(now);
            }
            return result;
        } finally {
            cycleRunning.set(false);
        }
    }

    public boolean startupHealthy() {
        return started.get() && !closed.get();
    }

    public boolean live() {
        return started.get() && !closed.get() && !executor.isShutdown()
                && !executor.isTerminated();
    }

    public boolean ready() {
        Instant success = lastSuccessfulCycle.get();
        return live() && success != null
                && !success.plus(settings.readinessMaximumStaleness()).isBefore(clock.instant());
    }

    public Instant lastSuccessfulCycle() {
        return lastSuccessfulCycle.get();
    }

    public CycleResult lastResult() {
        return lastResult.get();
    }

    public long totalFailures() {
        return totalFailures.get();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("webhook processor did not terminate");
                }
            }
        } catch (InterruptedException failure) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void runCycleSafely() {
        try {
            runCycle();
        } catch (RuntimeException failure) {
            totalFailures.incrementAndGet();
        }
    }
}
