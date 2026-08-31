package com.elmpay.gateway;

import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Production B39 wiring: bounded synchronous catch-up followed by tenant/project reads. */
public final class JdbcPaymentTimelineRuntime implements PaymentTimelineRuntime {
    interface Store {
        JdbcPaymentTimeline.ProjectionResult projectNextBatch(UUID tenantId, UUID projectId,
                String projectorName, int batchSize, Instant now);

        Optional<JdbcPaymentTimeline.PaymentStatus> findStatus(UUID tenantId, UUID projectId,
                UUID paymentIntentId);

        List<JdbcPaymentTimeline.TimelineEntry> timeline(UUID tenantId, UUID projectId,
                UUID paymentIntentId, long afterSequence, int limit);
    }

    private final Store store;
    private final String projectorName;
    private final int batchSize;
    private final int maximumBatches;
    private final Clock clock;

    public JdbcPaymentTimelineRuntime(JdbcPaymentTimeline timeline, String projectorName,
            int batchSize, int maximumBatches, Clock clock) {
        this(adapter(Objects.requireNonNull(timeline, "timeline")), projectorName, batchSize,
                maximumBatches, clock);
    }

    JdbcPaymentTimelineRuntime(Store store, String projectorName, int batchSize,
            int maximumBatches, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.projectorName = Objects.requireNonNull(projectorName, "projectorName");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (projectorName.isBlank() || projectorName.length() > 128) {
            throw new IllegalArgumentException("invalid projectorName");
        }
        if (batchSize < 1 || batchSize > 1_000 || maximumBatches < 1
                || maximumBatches > 1_000) {
            throw new IllegalArgumentException("invalid payment timeline catch-up bounds");
        }
        this.batchSize = batchSize;
        this.maximumBatches = maximumBatches;
    }

    @Override
    public Optional<JdbcPaymentTimeline.PaymentStatus> status(UUID tenantId, UUID projectId,
            UUID paymentIntentId) {
        requireScope(tenantId, projectId, paymentIntentId);
        catchUp(tenantId, projectId);
        return store.findStatus(tenantId, projectId, paymentIntentId);
    }

    @Override
    public Optional<TimelinePage> timeline(UUID tenantId, UUID projectId, UUID paymentIntentId,
            long afterSequence, int limit) {
        requireScope(tenantId, projectId, paymentIntentId);
        if (afterSequence < 0 || limit < 1 || limit > 100) {
            throw new IllegalArgumentException("invalid timeline cursor or limit");
        }
        catchUp(tenantId, projectId);
        Optional<JdbcPaymentTimeline.PaymentStatus> status = store.findStatus(tenantId, projectId,
                paymentIntentId);
        return status.map(value -> new TimelinePage(value,
                store.timeline(tenantId, projectId, paymentIntentId, afterSequence, limit)));
    }

    private void catchUp(UUID tenantId, UUID projectId) {
        for (int batch = 0; batch < maximumBatches; batch++) {
            JdbcPaymentTimeline.ProjectionResult result = store.projectNextBatch(tenantId,
                    projectId, projectorName, batchSize, clock.instant());
            if (result.caughtUp()) {
                return;
            }
        }
        throw new PaymentCoreException("READ_MODEL_LAGGING",
                "payment timeline could not catch up within the configured request bound");
    }

    private static Store adapter(JdbcPaymentTimeline timeline) {
        return new Store() {
            @Override
            public JdbcPaymentTimeline.ProjectionResult projectNextBatch(UUID tenantId,
                    UUID projectId, String name, int size, Instant now) {
                return timeline.projectNextBatch(tenantId, projectId, name, size, now);
            }

            @Override
            public Optional<JdbcPaymentTimeline.PaymentStatus> findStatus(UUID tenantId,
                    UUID projectId, UUID paymentIntentId) {
                return timeline.findStatus(tenantId, projectId, paymentIntentId);
            }

            @Override
            public List<JdbcPaymentTimeline.TimelineEntry> timeline(UUID tenantId, UUID projectId,
                    UUID paymentIntentId, long afterSequence, int limit) {
                return timeline.timeline(tenantId, projectId, paymentIntentId, afterSequence, limit);
            }
        };
    }

    private static void requireScope(UUID tenantId, UUID projectId, UUID paymentIntentId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(paymentIntentId, "paymentIntentId");
    }
}
