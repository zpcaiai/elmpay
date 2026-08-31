package com.elmpay.scheduler;

import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

/** Bounded worker wiring for incremental projection and operator-requested atomic rebuilds. */
public final class PaymentTimelineProjectionJob {
    private final JdbcPaymentTimeline timeline;
    private final UUID tenantId;
    private final UUID projectId;
    private final String projectorName;
    private final int batchSize;
    private final Clock clock;

    public PaymentTimelineProjectionJob(JdbcPaymentTimeline timeline, UUID tenantId,
            UUID projectId, String projectorName, int batchSize, Clock clock) {
        this.timeline = Objects.requireNonNull(timeline, "timeline");
        this.tenantId = Objects.requireNonNull(tenantId, "tenantId");
        this.projectId = Objects.requireNonNull(projectId, "projectId");
        this.projectorName = Objects.requireNonNull(projectorName, "projectorName");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (projectorName.isBlank() || batchSize < 1 || batchSize > 1_000) {
            throw new IllegalArgumentException("invalid projection job configuration");
        }
        this.batchSize = batchSize;
    }

    public PaymentTimelineProjectionJob(JdbcPaymentTimeline timeline, UUID tenantId,
            UUID projectId, PaymentTimelineProjectionSettings settings, Clock clock) {
        this(timeline, tenantId, projectId,
                Objects.requireNonNull(settings, "settings").projectorName(),
                settings.batchSize(), clock);
    }

    public JdbcPaymentTimeline.ProjectionResult runOnce() {
        return timeline.projectNextBatch(tenantId, projectId, projectorName, batchSize,
                clock.instant());
    }

    /** Bounded catch-up prevents an unbounded worker turn from starving other tenants. */
    public JdbcPaymentTimeline.ProjectionResult runUntilCaughtUp(int maximumBatches) {
        if (maximumBatches < 1 || maximumBatches > 10_000) {
            throw new IllegalArgumentException("maximumBatches is outside the safe bound");
        }
        JdbcPaymentTimeline.ProjectionResult result = runOnce();
        int totalApplied = result.appliedEvents();
        for (int batch = 1; batch < maximumBatches && !result.caughtUp(); batch++) {
            result = runOnce();
            totalApplied = Math.addExact(totalApplied, result.appliedEvents());
        }
        return new JdbcPaymentTimeline.ProjectionResult(totalApplied, result.checkpoint(),
                result.generation(), result.caughtUp());
    }

    public JdbcPaymentTimeline.ProjectionResult rebuild() {
        return timeline.rebuild(tenantId, projectId, projectorName, batchSize, clock.instant());
    }

    public JdbcPaymentTimeline.ProjectionResult runConfiguredCatchUp(
            PaymentTimelineProjectionSettings settings) {
        Objects.requireNonNull(settings, "settings");
        if (!projectorName.equals(settings.projectorName()) || batchSize != settings.batchSize()) {
            throw new IllegalArgumentException("settings do not match this projection job");
        }
        return runUntilCaughtUp(settings.maximumBatchesPerRun());
    }
}
