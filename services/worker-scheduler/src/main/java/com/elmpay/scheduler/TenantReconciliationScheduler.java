package com.elmpay.scheduler;

import com.elmpay.reconciliation.JdbcFinancialOperationsService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Bounded round-robin tenant/provider dispatcher with a durable oldest-first date cursor. */
public final class TenantReconciliationScheduler {
    public record Result(int completed, int failures) {
        public Result {
            if (completed < 0 || failures < 0) {
                throw new IllegalArgumentException("scheduler counters cannot be negative");
            }
        }
    }

    public interface ScheduleStore {
        LocalDate next(UUID tenantId, String provider, LocalDate latestEligible);

        void completed(UUID tenantId, String provider, LocalDate businessDate);

        void failed(UUID tenantId, String provider, LocalDate businessDate,
                String failureCode, String failureDigest);
    }

    private final ReconciliationSchedulerJob job;
    private final List<String> providers;
    private final Duration notBeforeDelay;
    private final int maximumJobsPerTenant;
    private final String workerId;
    private final ScheduleStore schedule;
    private final Map<UUID, Integer> cursors = new HashMap<>();

    public TenantReconciliationScheduler(ReconciliationSchedulerJob job, List<String> providers,
            Duration notBeforeDelay, int maximumJobsPerTenant, String workerId) {
        this(job, providers, notBeforeDelay, maximumJobsPerTenant, workerId,
                new InMemoryScheduleStore());
    }

    public TenantReconciliationScheduler(ReconciliationSchedulerJob job, List<String> providers,
            Duration notBeforeDelay, int maximumJobsPerTenant, String workerId,
            ScheduleStore schedule) {
        this.job = Objects.requireNonNull(job, "job");
        this.providers = List.copyOf(providers);
        this.notBeforeDelay = Objects.requireNonNull(notBeforeDelay, "notBeforeDelay");
        this.maximumJobsPerTenant = maximumJobsPerTenant;
        this.workerId = Objects.requireNonNull(workerId, "workerId");
        this.schedule = Objects.requireNonNull(schedule, "schedule");
        if (this.providers.isEmpty() || maximumJobsPerTenant < 1
                || maximumJobsPerTenant > this.providers.size()) {
            throw new IllegalArgumentException("invalid reconciliation scheduling bounds");
        }
    }

    public synchronized Result run(UUID tenantId, Instant now) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(now, "now");
        LocalDate latestEligible = now.minus(notBeforeDelay).atZone(ZoneOffset.UTC)
                .toLocalDate().minusDays(1);
        int start = Math.floorMod(cursors.getOrDefault(tenantId, 0), providers.size());
        int completed = 0;
        int failures = 0;
        int examined = 0;
        while (examined < providers.size()
                && completed + failures < maximumJobsPerTenant) {
            int index = (start + examined) % providers.size();
            String provider = providers.get(index);
            LocalDate businessDate = null;
            try {
                businessDate = schedule.next(tenantId, provider, latestEligible);
                if (businessDate != null) {
                    Instant cutoff = businessDate.plusDays(1).atStartOfDay(ZoneOffset.UTC)
                            .toInstant().plus(notBeforeDelay);
                    job.run(new ReconciliationSchedulerJob.SnapshotRequest(tenantId, provider,
                            businessDate, cutoff), workerId);
                    schedule.completed(tenantId, provider, businessDate);
                    completed = Math.addExact(completed, 1);
                }
            } catch (JdbcFinancialOperationsService.JobBusyException expectedCompetition) {
                // Another healthy replica owns the same durable job. No readiness failure.
            } catch (RuntimeException failure) {
                failures = Math.addExact(failures, 1);
                if (businessDate != null) {
                    String code = failureCode(failure);
                    try {
                        schedule.failed(tenantId, provider, businessDate, code,
                                failureDigest(tenantId, provider, businessDate, code));
                    } catch (RuntimeException persistenceFailure) {
                        persistenceFailure.addSuppressed(failure);
                        throw persistenceFailure;
                    }
                }
            }
            examined++;
        }
        cursors.put(tenantId, (start + Math.max(1, examined)) % providers.size());
        return new Result(completed, failures);
    }

    private static String failureCode(RuntimeException failure) {
        if (failure instanceof JdbcReconciliationFactSnapshotSource.MissingSourceException) {
            return "MISSING_SOURCE";
        }
        String value = failure.getClass().getSimpleName()
                .replaceAll("[^A-Za-z0-9]", "_").toUpperCase(java.util.Locale.ROOT);
        value = value.isBlank() ? "RUNTIME_FAILURE" : value;
        if (!Character.isLetter(value.charAt(0))) {
            value = "RUNTIME_" + value;
        }
        return value.substring(0, Math.min(value.length(), 64));
    }

    private static String failureDigest(UUID tenantId, String provider, LocalDate businessDate,
            String code) {
        String canonical = "elmpay.reconciliation.schedule-failure.v1\n"
                + "tenant_id=" + tenantId + "\nprovider=" + provider
                + "\nbusiness_date=" + businessDate + "\ncode=" + code + "\n";
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("JDK is missing SHA-256", impossible);
        }
    }

    /** Test-only fallback. Production always injects JdbcReconciliationScheduleStore. */
    private static final class InMemoryScheduleStore implements ScheduleStore {
        private final Map<String, LocalDate> dates = new HashMap<>();

        @Override
        public LocalDate next(UUID tenantId, String provider, LocalDate latestEligible) {
            LocalDate current = dates.computeIfAbsent(tenantId + ":" + provider,
                    ignored -> latestEligible);
            return current.isAfter(latestEligible) ? null : current;
        }

        @Override
        public void completed(UUID tenantId, String provider, LocalDate businessDate) {
            dates.compute(tenantId + ":" + provider, (ignored, current) -> {
                if (current == null || current.equals(businessDate)) {
                    return businessDate.plusDays(1);
                }
                if (current.isAfter(businessDate)) {
                    return current;
                }
                throw new IllegalStateException("reconciliation cursor cannot skip a business day");
            });
        }

        @Override
        public void failed(UUID tenantId, String provider, LocalDate businessDate,
                String failureCode, String failureDigest) {
            // Test-only fallback intentionally keeps only the durable cursor date semantics.
        }
    }
}
