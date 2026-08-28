package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.reconciliation.FinancialOperationsService;
import com.elmpay.reconciliation.ReconciliationEngine;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;

final class ReconciliationSchedulerJobTest {
    @Test
    void schedulerPassesImmutableSnapshotToDurableRuntime() {
        FinancialOperationsService financial = (FinancialOperationsService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] {FinancialOperationsService.class},
                (proxy, method, arguments) -> new FinancialOperationsService.ReconciliationResult(
                        "run-1", 1, 0));
        var command = new FinancialOperationsService.ReconciliationCommand(
                "00000000-0000-0000-0000-000000000001", "stripe",
                LocalDate.of(2026, 8, 28), Instant.EPOCH, "a".repeat(64), "b".repeat(64));
        var fact = new ReconciliationEngine.Fact(ReconciliationEngine.Source.PLATFORM,
                command.tenantId(), "order", "CAPTURE", 100, "USD", Instant.EPOCH, "digest");
        var result = new ReconciliationSchedulerJob(financial, ignored -> List.of(fact))
                .run(command, "worker");
        assertEquals("run-1", result.runId());
        assertThrows(IllegalStateException.class,
                () -> new ReconciliationSchedulerJob(financial, ignored -> List.of())
                        .run(command, "worker"));
    }
}
