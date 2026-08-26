package com.elmpay.scheduler;

import java.util.Objects;

/** Passes the fencing token to the sink so stale workers cannot commit effects. */
public final class FencedJobRunner {
    @FunctionalInterface
    public interface FencedWork<T> {
        T execute(long fencingToken);
    }

    private final FencedLeaseManager leases;

    public FencedJobRunner(FencedLeaseManager leases) {
        this.leases = Objects.requireNonNull(leases, "leases");
    }

    public <T> T run(FencedLeaseManager.Lease lease, FencedWork<T> work) {
        Objects.requireNonNull(work, "work");
        leases.assertCurrent(lease);
        T result = work.execute(lease.fencingToken());
        leases.assertCurrent(lease);
        return result;
    }
}
