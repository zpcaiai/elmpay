package com.elmpay.reconciliation;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/** Runtime boundary for B75-B79 statement intake, reconciliation and signed reporting. */
public interface FinancialOperationsService {
    record ReconciliationCommand(String tenantId, String provider, LocalDate businessDate,
            Instant cutoff, String sourceFileDigest, String inputManifestDigest) {}

    record ReconciliationResult(String runId, long matched, long exceptions) {}

    record SignedReport(FinancialReportService.Report report, String objectDigest) {}

    record Settlement(String providerBatchId, String currency, long grossMinor, long feeMinor,
            long expectedBankMinor, Instant expectedArrival, String providerStatus) {}

    record ExceptionItem(String id, String matchKey, String status, String owner,
            long adjustmentMinor, String currency, long version, Instant updatedAt) {}

    StatementIngestionService.Ingested ingestStatement(String tenantId,
            StatementIngestionService.Kind kind, String source, String parserVersion, byte[] raw);

    ReconciliationResult runReconciliation(ReconciliationCommand command,
            List<ReconciliationEngine.Fact> facts, String workerId);

    SignedReport generateReport(String tenantId, Instant from, Instant to);

    List<Settlement> settlements(String tenantId, Instant from, Instant to, int limit);

    List<ExceptionItem> exceptions(String tenantId, int limit);

    ExceptionItem claimException(String tenantId, String exceptionId, String actorId,
            String reason, String ticketId);

    ExceptionItem proposeAdjustment(String tenantId, String exceptionId, String actorId,
            long adjustmentMinor, String currency, String reason, String ticketId);

    ExceptionItem approveAdjustment(String tenantId, String exceptionId, String actorId,
            String ledgerTransactionId, String reason, String ticketId);

    ExceptionItem rejectAdjustment(String tenantId, String exceptionId, String actorId,
            String reason, String ticketId);
}
