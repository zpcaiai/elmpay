package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.reconciliation.FinancialOperationsService;
import com.elmpay.reconciliation.ReconciliationEngine;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class ReconciliationSchedulerJobTest {
    private static final UUID TENANT =
            UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID RUN =
            UUID.fromString("00000000-0000-0000-0000-000000000099");
    private static final Instant CUTOFF = Instant.parse("2026-08-29T02:00:00Z");

    @Test
    void schedulerDerivesCommandOnlyFromImmutableSnapshot() {
        AtomicReference<FinancialOperationsService.ReconciliationCommand> captured =
                new AtomicReference<>();
        FinancialOperationsService financial = financial(captured, new AtomicInteger());
        var request = new ReconciliationSchedulerJob.SnapshotRequest(TENANT, "stripe",
                LocalDate.of(2026, 8, 28), CUTOFF);
        var facts = facts("1", Instant.parse("2026-08-28T12:00:00Z"));
        var result = new ReconciliationSchedulerJob(financial, ignored ->
                new ReconciliationSchedulerJob.FactSnapshot(request, "a".repeat(64),
                        "b".repeat(64), facts)).run(request, "worker-1");
        assertEquals(RUN.toString(), result.runId());
        assertEquals("a".repeat(64), captured.get().sourceFileDigest());
        assertEquals("b".repeat(64), captured.get().inputManifestDigest());

        var otherTenant = new ReconciliationSchedulerJob.SnapshotRequest(UUID.randomUUID(),
                "stripe", request.businessDate(), request.cutoff());
        assertThrows(SecurityException.class, () -> new ReconciliationSchedulerJob(financial,
                ignored -> new ReconciliationSchedulerJob.FactSnapshot(otherTenant,
                        "a".repeat(64), "b".repeat(64), facts))
                .run(request, "worker-1"));
        assertThrows(IllegalStateException.class,
                () -> new ReconciliationSchedulerJob.FactSnapshot(request, "a".repeat(64),
                        "b".repeat(64), List.of()));
        assertThrows(IllegalStateException.class,
                () -> new ReconciliationSchedulerJob.FactSnapshot(request, "a".repeat(64),
                        "b".repeat(64), List.of(facts.getFirst())));
    }

    @Test
    void tenantDispatcherIsBoundedFairRestartSafeAndHonorsStableCutoff() {
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<FinancialOperationsService.ReconciliationCommand> captured =
                new AtomicReference<>();
        FinancialOperationsService financial = financial(captured, calls);
        ReconciliationSchedulerJob job = new ReconciliationSchedulerJob(financial, request ->
                new ReconciliationSchedulerJob.FactSnapshot(request, "a".repeat(64),
                        "b".repeat(64), facts(request.provider(),
                                request.businessDate().atTime(12, 0).toInstant(
                                        java.time.ZoneOffset.UTC))));
        TenantReconciliationScheduler scheduler = new TenantReconciliationScheduler(job,
                List.of("stripe", "paypal"), Duration.ofHours(2), 1, "worker-1");
        assertEquals(1, scheduler.run(TENANT, Instant.parse("2026-08-30T01:00:00Z"))
                .completed());
        assertEquals(1, scheduler.run(TENANT, Instant.parse("2026-08-30T01:01:00Z"))
                .completed());
        assertEquals(0, scheduler.run(TENANT, Instant.parse("2026-08-30T01:02:00Z"))
                .completed());
        assertEquals(1, scheduler.run(TENANT, Instant.parse("2026-08-30T02:00:00Z"))
                .completed());
        assertEquals(3, calls.get());
        assertEquals(LocalDate.of(2026, 8, 29), captured.get().businessDate());
        assertEquals(Instant.parse("2026-08-30T02:00:00Z"), captured.get().cutoff());
    }

    private static FinancialOperationsService financial(
            AtomicReference<FinancialOperationsService.ReconciliationCommand> captured,
            AtomicInteger calls) {
        return (FinancialOperationsService) Proxy.newProxyInstance(
                ReconciliationSchedulerJobTest.class.getClassLoader(),
                new Class<?>[] {FinancialOperationsService.class}, (proxy, method, arguments) -> {
                    if ("runReconciliation".equals(method.getName())) {
                        captured.set((FinancialOperationsService.ReconciliationCommand) arguments[0]);
                        calls.incrementAndGet();
                        return new FinancialOperationsService.ReconciliationResult(
                                RUN.toString(), 1, 0);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static ReconciliationEngine.Fact fact(ReconciliationEngine.Source source,
            String discriminator, long amount, Instant occurredAt) {
        String character = Integer.toHexString(Math.floorMod(discriminator.hashCode(), 16));
        return new ReconciliationEngine.Fact(source, TENANT.toString(), "1".repeat(64),
                "CAPTURE", amount, "USD", occurredAt,
                character.repeat(64));
    }

    private static List<ReconciliationEngine.Fact> facts(String discriminator,
            Instant occurredAt) {
        return java.util.Arrays.stream(ReconciliationEngine.Source.values())
                .map(source -> fact(source, discriminator + source.name(), 100, occurredAt))
                .toList();
    }
}
