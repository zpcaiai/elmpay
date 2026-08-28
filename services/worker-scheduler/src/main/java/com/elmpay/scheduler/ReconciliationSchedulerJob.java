package com.elmpay.scheduler;

import com.elmpay.reconciliation.FinancialOperationsService;
import com.elmpay.reconciliation.ReconciliationEngine;
import java.util.List;
import java.util.Objects;

/** Scheduled B77 entrypoint; fact snapshots are source-authenticated by the injected adapter. */
public final class ReconciliationSchedulerJob {
    @FunctionalInterface
    public interface FactSnapshotSource {
        List<ReconciliationEngine.Fact> snapshot(
                FinancialOperationsService.ReconciliationCommand command);
    }

    private final FinancialOperationsService financial;
    private final FactSnapshotSource source;

    public ReconciliationSchedulerJob(FinancialOperationsService financial,
            FactSnapshotSource source) {
        this.financial = Objects.requireNonNull(financial, "financial");
        this.source = Objects.requireNonNull(source, "source");
    }

    public FinancialOperationsService.ReconciliationResult run(
            FinancialOperationsService.ReconciliationCommand command, String workerId) {
        Objects.requireNonNull(command, "command");
        if (workerId == null || workerId.isBlank()) {
            throw new IllegalArgumentException("workerId is required");
        }
        List<ReconciliationEngine.Fact> facts = List.copyOf(source.snapshot(command));
        if (facts.isEmpty()) {
            throw new IllegalStateException("reconciliation fact snapshot is empty");
        }
        return financial.runReconciliation(command, facts, workerId);
    }
}
