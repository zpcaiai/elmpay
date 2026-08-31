package com.elmpay.scheduler;

import com.elmpay.reconciliation.FinancialOperationsService;
import com.elmpay.reconciliation.ReconciliationEngine;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Scheduled B77 entrypoint; commands are derived from one durable source snapshot. */
public final class ReconciliationSchedulerJob {
    public record SnapshotRequest(UUID tenantId, String provider, LocalDate businessDate,
            Instant cutoff) {
        public SnapshotRequest {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(businessDate, "businessDate");
            Objects.requireNonNull(cutoff, "cutoff");
            provider = normalizeProvider(provider);
            Instant end = businessDate.plusDays(1).atStartOfDay(java.time.ZoneOffset.UTC)
                    .toInstant();
            if (cutoff.isBefore(end) || cutoff.isAfter(end.plusSeconds(31L * 86_400))) {
                throw new IllegalArgumentException(
                        "cutoff must close the UTC business day within 31 days");
            }
        }
    }

    public record FactSnapshot(SnapshotRequest request, String sourceSetDigest,
            String inputManifestDigest, List<ReconciliationEngine.Fact> facts) {
        public FactSnapshot {
            Objects.requireNonNull(request, "request");
            if (!sha256(sourceSetDigest) || !sha256(inputManifestDigest)) {
                throw new IllegalArgumentException("snapshot digests must be SHA-256 hex");
            }
            facts = List.copyOf(facts);
            if (facts.isEmpty()) {
                throw new IllegalStateException("reconciliation fact snapshot is empty");
            }
            java.util.EnumSet<ReconciliationEngine.Source> sources = java.util.EnumSet.noneOf(
                    ReconciliationEngine.Source.class);
            facts.forEach(fact -> sources.add(fact.source()));
            if (!sources.equals(java.util.EnumSet.allOf(ReconciliationEngine.Source.class))) {
                throw new IllegalStateException(
                        "reconciliation fact snapshot must contain every governed source");
            }
            if (facts.stream().anyMatch(fact -> !request.tenantId().toString()
                    .equals(fact.tenantId()))) {
                throw new SecurityException("snapshot contains a cross-tenant fact");
            }
            Instant start = request.businessDate().atStartOfDay(java.time.ZoneOffset.UTC)
                    .toInstant();
            Instant end = request.businessDate().plusDays(1)
                    .atStartOfDay(java.time.ZoneOffset.UTC).toInstant();
            if (facts.stream().anyMatch(fact -> fact.occurredAt().isBefore(start)
                    || !fact.occurredAt().isBefore(end))) {
                throw new IllegalArgumentException(
                        "snapshot contains a fact outside the UTC business day");
            }
        }
    }

    @FunctionalInterface
    public interface FactSnapshotSource {
        FactSnapshot snapshot(SnapshotRequest request);
    }

    private final FinancialOperationsService financial;
    private final FactSnapshotSource source;

    public ReconciliationSchedulerJob(FinancialOperationsService financial,
            FactSnapshotSource source) {
        this.financial = Objects.requireNonNull(financial, "financial");
        this.source = Objects.requireNonNull(source, "source");
    }

    public FinancialOperationsService.ReconciliationResult run(SnapshotRequest request,
            String workerId) {
        Objects.requireNonNull(request, "request");
        if (workerId == null || !workerId.matches("[A-Za-z0-9][A-Za-z0-9._:-]{1,127}")) {
            throw new IllegalArgumentException("workerId is required");
        }
        FactSnapshot snapshot = Objects.requireNonNull(source.snapshot(request), "snapshot");
        if (!sameRequest(request, snapshot.request())) {
            throw new SecurityException("fact source returned a snapshot for another request");
        }
        FinancialOperationsService.ReconciliationCommand command =
                new FinancialOperationsService.ReconciliationCommand(
                        request.tenantId().toString(), request.provider(),
                        request.businessDate(), request.cutoff(), snapshot.sourceSetDigest(),
                        snapshot.inputManifestDigest());
        return financial.runReconciliation(command, snapshot.facts(), workerId);
    }

    private static boolean sameRequest(SnapshotRequest expected, SnapshotRequest actual) {
        return expected.tenantId().equals(actual.tenantId())
                && expected.provider().equals(actual.provider())
                && expected.businessDate().equals(actual.businessDate())
                && expected.cutoff().equals(actual.cutoff());
    }

    private static boolean sha256(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }

    private static String normalizeProvider(String value) {
        String normalized = Objects.requireNonNull(value, "provider").toLowerCase(Locale.ROOT);
        if (!Set.of("wechat", "alipay", "stripe", "paypal", "apple_pay")
                .contains(normalized)) {
            throw new IllegalArgumentException("unsupported reconciliation provider");
        }
        return normalized;
    }
}
