package com.elmpay.gateway;

import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Tenant/project-scoped access to the bounded, caught-up B39 payment read model. */
public interface PaymentTimelineRuntime {
    Optional<JdbcPaymentTimeline.PaymentStatus> status(UUID tenantId, UUID projectId,
            UUID paymentIntentId);

    Optional<TimelinePage> timeline(UUID tenantId, UUID projectId, UUID paymentIntentId,
            long afterSequence, int limit);

    record TimelinePage(JdbcPaymentTimeline.PaymentStatus status,
            List<JdbcPaymentTimeline.TimelineEntry> entries) {
        public TimelinePage {
            java.util.Objects.requireNonNull(status, "status");
            entries = List.copyOf(entries);
        }
    }

    static PaymentTimelineRuntime unavailable() {
        return Unavailable.INSTANCE;
    }

    enum Unavailable implements PaymentTimelineRuntime {
        INSTANCE;

        @Override
        public Optional<JdbcPaymentTimeline.PaymentStatus> status(UUID tenantId, UUID projectId,
                UUID paymentIntentId) {
            throw unavailableException();
        }

        @Override
        public Optional<TimelinePage> timeline(UUID tenantId, UUID projectId,
                UUID paymentIntentId, long afterSequence, int limit) {
            throw unavailableException();
        }

        private static PaymentCoreException unavailableException() {
            return new PaymentCoreException("READ_MODEL_UNAVAILABLE",
                    "payment timeline read model is unavailable in this runtime");
        }
    }
}
