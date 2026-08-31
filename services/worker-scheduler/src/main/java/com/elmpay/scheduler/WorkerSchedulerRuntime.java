package com.elmpay.scheduler;

import com.elmpay.admin.AdminActionPolicyBinding;
import com.elmpay.audit.AuditAnchorWorker;
import com.elmpay.payment.commerce.JdbcCommerceService;
import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
import com.elmpay.reconciliation.JdbcFinancialOperationsService;
import com.elmpay.scheduler.JdbcWorkerScopeRegistry.Scope;
import com.elmpay.scheduler.events.EventDeliverySettings;
import com.elmpay.scheduler.events.JdbcEventDeliveryStore;
import com.elmpay.scheduler.events.OutboxRelay;
import com.elmpay.scheduler.admin.RolloutAdminDomainCommandConsumer;
import com.elmpay.scheduler.admin.WorkerAdminCommandSchemaVerifier;
import com.elmpay.webhook.delivery.WebhookDeliveryService;
import com.elmpay.webhook.delivery.WebhookDeliveryRuntime;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;

/** Long-running, bounded and failure-isolated worker runtime. */
public final class WorkerSchedulerRuntime implements AutoCloseable {
    @FunctionalInterface
    public interface ReadinessDependency {
        boolean ready();
    }
    interface ScopeSource {
        void verifyRequiredSchema();

        List<Scope> activeScopes(int maximum, Scope after);
    }

    @FunctionalInterface
    interface TenantOutboxWork {
        int[] run(UUID tenantId, Instant now);
    }

    @FunctionalInterface
    interface TenantBillingWork {
        BillingLifecycleJob.Result run(UUID tenantId, Instant now);
    }

    @FunctionalInterface
    interface TenantAuxiliaryWork {
        void run(UUID tenantId);
    }

    @FunctionalInterface
    interface TenantReconciliationWork {
        TenantReconciliationScheduler.Result run(UUID tenantId, Instant now);
    }

    @FunctionalInterface
    interface ProjectTimelineWork {
        int run(Scope scope);
    }

    @FunctionalInterface
    interface PartitionWork {
        void run();
    }

    @FunctionalInterface
    interface AdminCommandWork {
        boolean run();
    }

    public record CycleResult(int scopes, int tenants, int publishedEvents,
            int retryScheduledEvents, int projectedEvents, int renewalEvents, int dunningEvents,
            int reconciliationRuns, int rolloutAdminCommands, boolean partitionMaintenanceRan,
            int failures) {
        public CycleResult {
            if (scopes < 0 || tenants < 0 || publishedEvents < 0 || retryScheduledEvents < 0
                    || projectedEvents < 0 || renewalEvents < 0 || dunningEvents < 0
                    || reconciliationRuns < 0 || rolloutAdminCommands < 0 || failures < 0) {
                throw new IllegalArgumentException("cycle counters cannot be negative");
            }
        }

        public CycleResult(int scopes, int tenants, int publishedEvents,
                int retryScheduledEvents, int projectedEvents, int renewalEvents,
                int dunningEvents, boolean partitionMaintenanceRan, int failures) {
            this(scopes, tenants, publishedEvents, retryScheduledEvents, projectedEvents,
                    renewalEvents, dunningEvents, 0, 0, partitionMaintenanceRan, failures);
        }

        public boolean successful() {
            return failures == 0;
        }
    }

    private final WorkerSchedulerSettings settings;
    private final ScopeSource scopeSource;
    private final TenantOutboxWork outboxWork;
    private final TenantBillingWork billingWork;
    private final TenantAuxiliaryWork auditAnchorWork;
    private final TenantAuxiliaryWork webhookDeliveryWork;
    private final TenantReconciliationWork reconciliationWork;
    private final ProjectTimelineWork timelineWork;
    private final PartitionWork partitionWork;
    private final boolean partitionWorkEnabled;
    private final AdminCommandWork rolloutAdminWork;
    private final Clock clock;
    private final ScheduledExecutorService executor;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean cycleRunning = new AtomicBoolean();
    private final AtomicReference<Instant> lastSuccessfulCycle = new AtomicReference<>();
    private final AtomicReference<Instant> lastCompletedCycle = new AtomicReference<>();
    private final AtomicReference<LocalDate> lastPartitionMaintenance = new AtomicReference<>();
    private final AtomicReference<CycleResult> lastResult = new AtomicReference<>();
    private final AtomicReference<Scope> scopeCursor = new AtomicReference<>();
    private final AtomicLong totalFailures = new AtomicLong();
    private final ReadinessDependency readinessDependency;

    public WorkerSchedulerRuntime(WorkerSchedulerSettings settings,
            EventDeliverySettings eventSettings, DataSource dataSource,
            OutboxRelay.Publisher publisher, PaymentTimelineProjectionSettings projectionSettings,
            Clock clock) {
        this(settings, eventSettings, dataSource, publisher, projectionSettings, clock, () -> true);
    }

    public WorkerSchedulerRuntime(WorkerSchedulerSettings settings,
            EventDeliverySettings eventSettings, DataSource dataSource,
            OutboxRelay.Publisher publisher, PaymentTimelineProjectionSettings projectionSettings,
            Clock clock, ReadinessDependency readinessDependency) {
        this(settings, eventSettings, dataSource, publisher, projectionSettings, clock,
                readinessDependency, tenantId -> { }, tenantId -> { });
    }

    /**
     * Production composition with mounted audit timestamping and webhook-signing dependencies.
     * All external TLS/token/trust mounts are validated before the runtime object is returned.
     */
    public static WorkerSchedulerRuntime production(WorkerSchedulerSettings settings,
            EventDeliverySettings eventSettings, DataSource dataSource,
            OutboxRelay.Publisher publisher, PaymentTimelineProjectionSettings projectionSettings,
            Clock clock, ReadinessDependency readinessDependency,
            Map<String, String> environment) {
        AuditAnchorWorker audit = AuditAnchorWorker.fromEnvironment(dataSource, environment, clock);
        WebhookDeliveryRuntime webhooks = WebhookDeliveryRuntime.fromEnvironment(
                dataSource, environment, clock);
        return new WorkerSchedulerRuntime(settings, eventSettings, dataSource, publisher,
                projectionSettings, clock, readinessDependency,
                tenantId -> {
                    AuditAnchorWorker.Outcome outcome = audit.runOnce(tenantId);
                    if (outcome == AuditAnchorWorker.Outcome.RETRY_SCHEDULED) {
                        throw new IllegalStateException(
                                "audit timestamp dependency scheduled a retry");
                    }
                }, tenantId -> {
                    WebhookDeliveryService.Outcome outcome =
                            webhooks.runOnce(tenantId.toString());
                    if (outcome == WebhookDeliveryService.Outcome.RETRY_SCHEDULED
                            || outcome == WebhookDeliveryService.Outcome.DEAD_LETTERED) {
                        throw new IllegalStateException(
                                "webhook delivery dependency did not complete successfully");
                    }
                });
    }

    private WorkerSchedulerRuntime(WorkerSchedulerSettings settings,
            EventDeliverySettings eventSettings, DataSource dataSource,
            OutboxRelay.Publisher publisher, PaymentTimelineProjectionSettings projectionSettings,
            Clock clock, ReadinessDependency readinessDependency,
            TenantAuxiliaryWork auditAnchorWork, TenantAuxiliaryWork webhookDeliveryWork) {
        this.settings = Objects.requireNonNull(settings, "settings");
        Objects.requireNonNull(eventSettings, "eventSettings");
        Objects.requireNonNull(dataSource, "dataSource");
        JdbcWorkerScopeRegistry registry = new JdbcWorkerScopeRegistry(dataSource);
        WorkerAdminCommandSchemaVerifier adminSchema =
                new WorkerAdminCommandSchemaVerifier(dataSource);
        this.scopeSource = new ScopeSource() {
            @Override
            public void verifyRequiredSchema() {
                registry.verifyRequiredSchema();
                adminSchema.verify();
            }

            @Override
            public List<Scope> activeScopes(int maximum, Scope after) {
                return registry.activeScopes(maximum, after);
            }
        };
        OutboxRelay relay = eventSettings.relay(new JdbcEventDeliveryStore(dataSource),
                Objects.requireNonNull(publisher, "publisher"));
        this.outboxWork = (tenantId, now) -> drainOutbox(relay, tenantId, now, settings);
        JdbcCommerceService commerce = new JdbcCommerceService(dataSource,
                Objects.requireNonNull(clock, "clock"));
        this.billingWork = (tenantId, now) -> new BillingLifecycleJob(commerce,
                settings.maximumBillingItemsPerTenant()).run(tenantId, settings.workerId(), now);
        this.auditAnchorWork = Objects.requireNonNull(auditAnchorWork, "auditAnchorWork");
        this.webhookDeliveryWork = Objects.requireNonNull(
                webhookDeliveryWork, "webhookDeliveryWork");
        JdbcFinancialOperationsService financial =
                JdbcFinancialOperationsService.reconciliationOnly(dataSource, clock,
                        settings.reconciliationJobLease());
        ReconciliationSchedulerJob reconciliation = new ReconciliationSchedulerJob(financial,
                new JdbcReconciliationFactSnapshotSource(dataSource, clock,
                        settings.reconciliationMaximumFacts()));
        TenantReconciliationScheduler tenantReconciliation = new TenantReconciliationScheduler(
                reconciliation, settings.reconciliationProviders(),
                settings.reconciliationNotBeforeDelay(),
                settings.maximumReconciliationJobsPerTenant(), settings.workerId(),
                new JdbcReconciliationScheduleStore(dataSource, clock));
        this.reconciliationWork = tenantReconciliation::run;
        JdbcPaymentTimeline timeline = new JdbcPaymentTimeline(dataSource);
        PaymentTimelineProjectionSettings verifiedProjection = Objects.requireNonNull(
                projectionSettings, "projectionSettings");
        this.timelineWork = scope -> new PaymentTimelineProjectionJob(timeline,
                scope.tenantId(), scope.projectId(), verifiedProjection, clock)
                        .runUntilCaughtUp(settings.maximumTimelineBatchesPerProject())
                        .appliedEvents();
        // Long-running worker credentials are deliberately incapable of DDL.  Partition
        // precreation is owned by the separately credentialed maintenance Job/CronJob.
        this.partitionWork = () -> {
            throw new IllegalStateException(
                    "partition DDL is forbidden in the worker-scheduler runtime");
        };
        this.partitionWorkEnabled = false;
        AdminActionPolicyBinding adminPolicy = AdminActionPolicyBinding.load(
                settings.adminActionPolicyBindingFile());
        RolloutAdminDomainCommandConsumer rolloutAdmin =
                new RolloutAdminDomainCommandConsumer(dataSource, settings.workerId(),
                        settings.adminCommandLease(), adminPolicy);
        this.rolloutAdminWork = () -> rolloutAdmin.runOnce()
                != RolloutAdminDomainCommandConsumer.Outcome.IDLE;
        this.clock = clock;
        ReadinessDependency external = Objects.requireNonNull(readinessDependency,
                "readinessDependency");
        this.readinessDependency = () -> external.ready()
                && adminPolicy.validUntil().isAfter(clock.instant());
        this.executor = newExecutor();
    }

    WorkerSchedulerRuntime(WorkerSchedulerSettings settings, Clock clock,
            ScopeSource scopeSource, TenantOutboxWork outboxWork,
            TenantBillingWork billingWork, ProjectTimelineWork timelineWork,
            PartitionWork partitionWork) {
        this(settings, clock, scopeSource, outboxWork, billingWork, timelineWork, partitionWork,
                () -> false);
    }

    WorkerSchedulerRuntime(WorkerSchedulerSettings settings, Clock clock,
            ScopeSource scopeSource, TenantOutboxWork outboxWork,
            TenantBillingWork billingWork, ProjectTimelineWork timelineWork,
            PartitionWork partitionWork, AdminCommandWork rolloutAdminWork) {
        this(settings, clock, scopeSource, outboxWork, billingWork, timelineWork, partitionWork,
                rolloutAdminWork, tenantId -> { }, tenantId -> { });
    }

    WorkerSchedulerRuntime(WorkerSchedulerSettings settings, Clock clock,
            ScopeSource scopeSource, TenantOutboxWork outboxWork,
            TenantBillingWork billingWork, ProjectTimelineWork timelineWork,
            PartitionWork partitionWork, AdminCommandWork rolloutAdminWork,
            TenantAuxiliaryWork auditAnchorWork, TenantAuxiliaryWork webhookDeliveryWork) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.scopeSource = Objects.requireNonNull(scopeSource, "scopeSource");
        this.outboxWork = Objects.requireNonNull(outboxWork, "outboxWork");
        this.billingWork = Objects.requireNonNull(billingWork, "billingWork");
        this.auditAnchorWork = Objects.requireNonNull(auditAnchorWork, "auditAnchorWork");
        this.webhookDeliveryWork = Objects.requireNonNull(
                webhookDeliveryWork, "webhookDeliveryWork");
        this.reconciliationWork = (tenantId, now) ->
                new TenantReconciliationScheduler.Result(0, 0);
        this.timelineWork = Objects.requireNonNull(timelineWork, "timelineWork");
        this.partitionWork = Objects.requireNonNull(partitionWork, "partitionWork");
        this.partitionWorkEnabled = true;
        this.rolloutAdminWork = Objects.requireNonNull(rolloutAdminWork, "rolloutAdminWork");
        this.readinessDependency = () -> true;
        this.executor = newExecutor();
    }

    private ScheduledExecutorService newExecutor() {
        ThreadFactory threads = runnable -> {
            Thread thread = new Thread(runnable, "elmpay-worker-cycle");
            thread.setDaemon(false);
            thread.setUncaughtExceptionHandler((ignored, failure) -> recordFailure("uncaught",
                    failure));
            return thread;
        };
        return Executors.newSingleThreadScheduledExecutor(threads);
    }

    public synchronized void start() {
        if (started.get()) {
            throw new IllegalStateException("worker runtime is already started");
        }
        if (closed.get()) {
            throw new IllegalStateException("closed worker runtime cannot start");
        }
        scopeSource.verifyRequiredSchema();
        if (closed.get()) {
            throw new IllegalStateException("worker runtime closed during schema validation");
        }
        started.set(true);
        try {
            executor.scheduleWithFixedDelay(this::runCycleSafely, 0,
                    settings.pollInterval().toMillis(), TimeUnit.MILLISECONDS);
        } catch (RuntimeException failure) {
            started.set(false);
            throw failure;
        }
    }

    /** Runs one complete fairness-bounded turn; exposed for deterministic runtime tests. */
    public CycleResult runCycle() {
        if (closed.get()) {
            throw new IllegalStateException("worker runtime is closed");
        }
        if (!cycleRunning.compareAndSet(false, true)) {
            throw new IllegalStateException("a worker cycle is already running");
        }
        try {
            Instant now = clock.instant();
            List<Scope> scopes = scopeSource.activeScopes(settings.maximumScopesPerCycle(),
                    scopeCursor.get());
            scopeCursor.set(scopes.isEmpty() ? null : scopes.getLast());
            Set<UUID> tenants = new HashSet<>();
            int published = 0;
            int retried = 0;
            int projected = 0;
            int renewals = 0;
            int dunning = 0;
            int reconciliationRuns = 0;
            int rolloutAdminCommands = 0;
            int failures = 0;
            try {
                for (int index = 0; index < settings.maximumAdminCommandsPerCycle(); index++) {
                    if (!rolloutAdminWork.run()) {
                        break;
                    }
                    rolloutAdminCommands = Math.addExact(rolloutAdminCommands, 1);
                }
            } catch (RuntimeException failure) {
                failures = Math.addExact(failures, 1);
                recordFailure("rollout-admin", failure);
            }
            for (Scope scope : scopes) {
                if (tenants.add(scope.tenantId())) {
                    try {
                        int[] counts = outboxWork.run(scope.tenantId(), now);
                        published = Math.addExact(published, counts[0]);
                        retried = Math.addExact(retried, counts[1]);
                    } catch (RuntimeException failure) {
                        failures = Math.addExact(failures, 1);
                        recordFailure("outbox", failure);
                    }
                    try {
                        BillingLifecycleJob.Result result = billingWork.run(scope.tenantId(), now);
                        renewals = Math.addExact(renewals, result.renewalEvents());
                        dunning = Math.addExact(dunning, result.dunningEvents());
                    } catch (RuntimeException failure) {
                        failures = Math.addExact(failures, 1);
                        recordFailure("billing", failure);
                    }
                    try {
                        auditAnchorWork.run(scope.tenantId());
                    } catch (RuntimeException failure) {
                        failures = Math.addExact(failures, 1);
                        recordFailure("audit-anchor", failure);
                    }
                    try {
                        webhookDeliveryWork.run(scope.tenantId());
                    } catch (RuntimeException failure) {
                        failures = Math.addExact(failures, 1);
                        recordFailure("webhook-delivery", failure);
                    }
                    try {
                        TenantReconciliationScheduler.Result result =
                                reconciliationWork.run(scope.tenantId(), now);
                        reconciliationRuns = Math.addExact(reconciliationRuns,
                                result.completed());
                        if (result.failures() > 0) {
                            failures = Math.addExact(failures, result.failures());
                            for (int index = 0; index < result.failures(); index++) {
                                recordFailure("reconciliation",
                                        new IllegalStateException("provider job failed"));
                            }
                        }
                    } catch (RuntimeException failure) {
                        failures = Math.addExact(failures, 1);
                        recordFailure("reconciliation", failure);
                    }
                }
                try {
                    projected = Math.addExact(projected, timelineWork.run(scope));
                } catch (RuntimeException failure) {
                    failures = Math.addExact(failures, 1);
                    recordFailure("timeline", failure);
                }
            }
            boolean partitionRan = false;
            LocalDate today = now.atZone(ZoneOffset.UTC).toLocalDate();
            if (partitionWorkEnabled && !today.equals(lastPartitionMaintenance.get())) {
                try {
                    partitionWork.run();
                    lastPartitionMaintenance.set(today);
                    partitionRan = true;
                } catch (RuntimeException failure) {
                    failures = Math.addExact(failures, 1);
                    recordFailure("partition", failure);
                }
            }
            CycleResult result = new CycleResult(scopes.size(), tenants.size(), published, retried,
                    projected, renewals, dunning, reconciliationRuns, rolloutAdminCommands,
                    partitionRan, failures);
            lastResult.set(result);
            lastCompletedCycle.set(now);
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
        CycleResult completed = lastResult.get();
        return live() && success != null && completed != null && completed.successful()
                && !success.plus(settings.readinessMaximumStaleness()).isBefore(clock.instant())
                && readinessDependency.ready();
    }

    public Instant lastSuccessfulCycle() {
        return lastSuccessfulCycle.get();
    }

    public Instant lastCompletedCycle() {
        return lastCompletedCycle.get();
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
                    throw new IllegalStateException("worker executor did not terminate");
                }
            }
        } catch (InterruptedException failure) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static int[] drainOutbox(OutboxRelay relay, UUID tenantId, Instant now,
            WorkerSchedulerSettings settings) {
        int published = 0;
        int retried = 0;
        for (int index = 0; index < settings.maximumOutboxMessagesPerTenant(); index++) {
            OutboxRelay.Outcome outcome = relay.runOnce(tenantId, settings.workerId(), now);
            if (outcome == OutboxRelay.Outcome.IDLE) {
                break;
            }
            if (outcome == OutboxRelay.Outcome.PUBLISHED) {
                published = Math.addExact(published, 1);
            } else {
                retried = Math.addExact(retried, 1);
            }
        }
        return new int[] {published, retried};
    }

    private void runCycleSafely() {
        try {
            runCycle();
        } catch (RuntimeException failure) {
            lastCompletedCycle.set(clock.instant());
            recordFailure("cycle", failure);
        }
    }

    private void recordFailure(String stage, Throwable failure) {
        totalFailures.incrementAndGet();
        // Never emit exception messages: provider/JDBC clients may include request metadata.
        System.err.println("elmpay_worker_failure stage=" + stage + " code="
                + failure.getClass().getSimpleName());
    }

}
