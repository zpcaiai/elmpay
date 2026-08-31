package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class JdbcPaymentTimelineRuntimeTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final UUID TENANT = UUID.randomUUID();
    private static final UUID PROJECT = UUID.randomUUID();
    private static final UUID INTENT = UUID.randomUUID();

    @Test
    void catchesUpWithinBoundBeforeReadingStatus() {
        FakeStore store = new FakeStore(false, false, true);
        JdbcPaymentTimelineRuntime runtime = new JdbcPaymentTimelineRuntime(store, "test-v1", 10,
                3, Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(INTENT, runtime.status(TENANT, PROJECT, INTENT).orElseThrow()
                .paymentIntentId());
        assertEquals(3, store.projectCalls);
        assertEquals(1, store.statusCalls);
    }

    @Test
    void failsClosedWithoutReadingWhenCatchUpBoundIsExhausted() {
        FakeStore store = new FakeStore(false, false, true);
        JdbcPaymentTimelineRuntime runtime = new JdbcPaymentTimelineRuntime(store, "test-v1", 10,
                2, Clock.fixed(NOW, ZoneOffset.UTC));

        PaymentCoreException failure = assertThrows(PaymentCoreException.class,
                () -> runtime.timeline(TENANT, PROJECT, INTENT, 0, 100));
        assertEquals("READ_MODEL_LAGGING", failure.code());
        assertEquals(2, store.projectCalls);
        assertEquals(0, store.statusCalls);
        assertEquals(0, store.timelineCalls);
    }

    private static final class FakeStore implements JdbcPaymentTimelineRuntime.Store {
        private final Queue<Boolean> caughtUp;
        private int projectCalls;
        private int statusCalls;
        private int timelineCalls;

        private FakeStore(Boolean... caughtUp) {
            this.caughtUp = new ArrayDeque<>(List.of(caughtUp));
        }

        @Override
        public JdbcPaymentTimeline.ProjectionResult projectNextBatch(UUID tenantId, UUID projectId,
                String projectorName, int batchSize, Instant now) {
            projectCalls++;
            return new JdbcPaymentTimeline.ProjectionResult(0, projectCalls, 1,
                    caughtUp.remove());
        }

        @Override
        public Optional<JdbcPaymentTimeline.PaymentStatus> findStatus(UUID tenantId,
                UUID projectId, UUID paymentIntentId) {
            statusCalls++;
            return Optional.of(status());
        }

        @Override
        public List<JdbcPaymentTimeline.TimelineEntry> timeline(UUID tenantId, UUID projectId,
                UUID paymentIntentId, long afterSequence, int limit) {
            timelineCalls++;
            return List.of();
        }

        private static JdbcPaymentTimeline.PaymentStatus status() {
            return new JdbcPaymentTimeline.PaymentStatus(TENANT, PROJECT, INTENT, "captured",
                    1_000, "USD", 1_000, 0, "stripe", "pi_1", "SUCCEEDED",
                    "APPROVED", 3, 1, NOW);
        }
    }
}
