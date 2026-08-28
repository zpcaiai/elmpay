package com.elmpay.scheduler;

import com.elmpay.payment.commerce.CommerceService;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Bounded production entrypoint for durable subscription renewal and dunning outbox work. */
public final class BillingLifecycleJob {
    public record Result(int renewalEvents, int dunningEvents) {}

    private final CommerceService commerce;
    private final int maximumItemsPerRun;

    public BillingLifecycleJob(CommerceService commerce, int maximumItemsPerRun) {
        this.commerce = Objects.requireNonNull(commerce, "commerce");
        if (maximumItemsPerRun <= 0 || maximumItemsPerRun > 10_000) {
            throw new IllegalArgumentException("bounded maximumItemsPerRun is required");
        }
        this.maximumItemsPerRun = maximumItemsPerRun;
    }

    /**
     * Each service call uses SERIALIZABLE + SKIP LOCKED and emits an outbox row in the same
     * transaction. Re-running is safe because billing-cycle and dunning identities are unique.
     */
    public Result run(UUID tenantId, String workerId, Instant now) {
        Objects.requireNonNull(tenantId, "tenantId");
        if (workerId == null || workerId.isBlank()) {
            throw new IllegalArgumentException("workerId is required");
        }
        Objects.requireNonNull(now, "now");
        int renewals = 0;
        int dunning = 0;
        for (int index = 0; index < maximumItemsPerRun; index++) {
            if (commerce.enqueueDueRenewal(tenantId, now, workerId).isEmpty()) {
                break;
            }
            renewals++;
        }
        for (int index = 0; index < maximumItemsPerRun; index++) {
            if (commerce.enqueueDueDunning(tenantId, now, workerId).isEmpty()) {
                break;
            }
            dunning++;
        }
        return new Result(renewals, dunning);
    }
}
