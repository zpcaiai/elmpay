package com.elmpay.reconciliation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL financial runtime with durable jobs and KMS-versioned report manifests. */
public final class JdbcFinancialOperationsService implements FinancialOperationsService {
    private static final Duration JOB_LEASE = Duration.ofMinutes(10);
    private final DataSource dataSource;
    private final Clock clock;
    private final StatementIngestionService statements;
    private final ReconciliationEngine engine;
    private final ReconciliationRepository repository;
    private final FinancialReportService reports;

    public JdbcFinancialOperationsService(DataSource dataSource, Clock clock,
            ExportManifestSigner signer, int maximumStatementBytes, int maximumStatementRows) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.statements = new StatementIngestionService(dataSource, clock, maximumStatementBytes,
                maximumStatementRows);
        this.engine = new ReconciliationEngine();
        this.repository = new ReconciliationRepository(dataSource, clock);
        this.reports = new FinancialReportService(signer);
    }

    @Override
    public StatementIngestionService.Ingested ingestStatement(String tenantId,
            StatementIngestionService.Kind kind, String source, String parserVersion, byte[] raw) {
        try {
            return statements.ingest(tenantId, kind, source, parserVersion, raw);
        } catch (SQLException failure) {
            throw persistence("statement ingestion failed", failure);
        }
    }

    @Override
    public ReconciliationResult runReconciliation(ReconciliationCommand command,
            List<ReconciliationEngine.Fact> facts, String workerId) {
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(facts, "facts");
        required(workerId, "workerId");
        UUID tenant = TenantSession.tenant(command.tenantId());
        String jobName = "reconciliation:" + provider(command.provider());
        long fencingToken = claimJob(tenant, jobName, command.businessDate(), workerId,
                command.inputManifestDigest());
        try {
            ReconciliationEngine.Run run = engine.reconcile(command.tenantId(), command.cutoff(),
                    List.copyOf(facts));
            String runId = repository.saveRun(run, command.provider(), command.businessDate(),
                    command.sourceFileDigest(), command.inputManifestDigest());
            finishJob(tenant, jobName, command.businessDate(), workerId, fencingToken, runId,
                    null);
            return new ReconciliationResult(runId, run.matched(), run.exceptions());
        } catch (RuntimeException | SQLException failure) {
            try {
                finishJob(tenant, jobName, command.businessDate(), workerId, fencingToken, null,
                        failure.getClass().getSimpleName());
            } catch (RuntimeException finishFailure) {
                failure.addSuppressed(finishFailure);
            }
            if (failure instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw persistence("reconciliation run failed", failure);
        }
    }

    @Override
    public SignedReport generateReport(String tenantId, Instant from, Instant to) {
        UUID tenant = TenantSession.tenant(tenantId);
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        if (!from.isBefore(to) || Duration.between(from, to).compareTo(Duration.ofDays(370)) > 0) {
            throw new IllegalArgumentException("report interval is invalid or too large");
        }
        List<FinancialReportService.Fact> facts = facts(tenant, from, to);
        FinancialReportService.Report report = reports.generate(tenantId, from, to, facts);
        byte[] artifact = artifact(report);
        try {
            return new SignedReport(report, repository.saveExport(report, artifact));
        } catch (SQLException failure) {
            throw persistence("financial export could not be persisted", failure);
        }
    }

    @Override
    public List<Settlement> settlements(String tenantId, Instant from, Instant to, int limit) {
        UUID tenant = TenantSession.tenant(tenantId);
        bounded(limit);
        return query(tenant, connection -> {
            List<Settlement> values = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT provider_batch_id,currency,gross_minor,fee_minor,expected_bank_minor,
                           expected_arrival,provider_status
                      FROM settlement_instruction
                     WHERE tenant_id=? AND expected_arrival>=? AND expected_arrival<?
                     ORDER BY expected_arrival,provider_batch_id LIMIT ?
                    """)) {
                statement.setObject(1, tenant);
                statement.setTimestamp(2, Timestamp.from(from));
                statement.setTimestamp(3, Timestamp.from(to));
                statement.setInt(4, limit);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        values.add(new Settlement(result.getString(1), result.getString(2),
                                result.getLong(3), result.getLong(4), result.getLong(5),
                                result.getTimestamp(6).toInstant(), result.getString(7)));
                    }
                }
            }
            return List.copyOf(values);
        });
    }

    @Override
    public List<ExceptionItem> exceptions(String tenantId, int limit) {
        UUID tenant = TenantSession.tenant(tenantId);
        bounded(limit);
        return query(tenant, connection -> {
            List<ExceptionItem> values = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT id,match_key,status,owner_id,adjustment_minor,currency,version,updated_at
                      FROM recon_exception_current WHERE tenant_id=?
                     ORDER BY updated_at DESC,id LIMIT ?
                    """)) {
                statement.setObject(1, tenant);
                statement.setInt(2, limit);
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        values.add(new ExceptionItem(result.getString(1), result.getString(2),
                                result.getString(3), result.getString(4), result.getLong(5),
                                result.getString(6), result.getLong(7),
                                result.getTimestamp(8).toInstant()));
                    }
                }
            }
            return List.copyOf(values);
        });
    }

    @Override
    public ExceptionItem claimException(String tenantId, String exceptionId, String actorId,
            String reason, String ticketId) {
        return transition(tenantId, exceptionId, actorId, reason, ticketId,
                ExceptionAction.CLAIM, 0L, null, null);
    }

    @Override
    public ExceptionItem proposeAdjustment(String tenantId, String exceptionId, String actorId,
            long adjustmentMinor, String currency, String reason, String ticketId) {
        if (adjustmentMinor == 0 || currency == null || !currency.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("non-zero adjustment and currency are required");
        }
        return transition(tenantId, exceptionId, actorId, reason, ticketId,
                ExceptionAction.PROPOSE, adjustmentMinor, currency, null);
    }

    @Override
    public ExceptionItem approveAdjustment(String tenantId, String exceptionId, String actorId,
            String ledgerTransactionId, String reason, String ticketId) {
        UUID ledgerId = UUID.fromString(ledgerTransactionId);
        return transition(tenantId, exceptionId, actorId, reason, ticketId,
                ExceptionAction.APPROVE, 0L, null, ledgerId);
    }

    @Override
    public ExceptionItem rejectAdjustment(String tenantId, String exceptionId, String actorId,
            String reason, String ticketId) {
        return transition(tenantId, exceptionId, actorId, reason, ticketId,
                ExceptionAction.REJECT, 0L, null, null);
    }

    private ExceptionItem transition(String tenantId, String exceptionId, String actorId,
            String reason, String ticketId, ExceptionAction action, long amount, String currency,
            UUID ledgerTransactionId) {
        UUID tenant = TenantSession.tenant(tenantId);
        UUID id = UUID.fromString(exceptionId);
        required(actorId, "actorId");
        required(reason, "reason");
        required(ticketId, "ticketId");
        return query(tenant, connection -> {
            ExceptionItem before = exception(connection, tenant, id, true);
            String status;
            String owner = before.owner();
            String proposer = null;
            String approver = null;
            long adjustment = before.adjustmentMinor();
            String adjustmentCurrency = before.currency();
            switch (action) {
                case CLAIM -> {
                    if (!"OPEN".equals(before.status()) || owner != null) {
                        throw new IllegalStateException("exception is not open for claim");
                    }
                    status = "CLAIMED";
                    owner = actorId;
                }
                case PROPOSE -> {
                    if (!"CLAIMED".equals(before.status()) || !actorId.equals(owner)) {
                        throw new SecurityException("only the case owner may propose adjustment");
                    }
                    status = "ADJUSTMENT_PROPOSED";
                    proposer = actorId;
                    adjustment = amount;
                    adjustmentCurrency = currency;
                }
                case APPROVE -> {
                    CurrentActors actors = actors(connection, tenant, id);
                    if (!"ADJUSTMENT_PROPOSED".equals(before.status())
                            || actorId.equals(actors.proposer())) {
                        throw new SecurityException("distinct approver is required");
                    }
                    status = "RESOLVED";
                    proposer = actors.proposer();
                    approver = actorId;
                }
                case REJECT -> {
                    CurrentActors actors = actors(connection, tenant, id);
                    if (!"ADJUSTMENT_PROPOSED".equals(before.status())
                            || actorId.equals(actors.proposer())) {
                        throw new SecurityException("distinct reviewer is required");
                    }
                    status = "REJECTED";
                    proposer = actors.proposer();
                    approver = actorId;
                }
                default -> throw new IllegalStateException("unsupported exception action");
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE recon_exception_current
                       SET status=?,owner_id=?,proposer_id=?,approver_id=?,adjustment_minor=?,
                           currency=?,version=version+1,updated_at=?
                     WHERE id=? AND tenant_id=? AND version=?
                    """)) {
                statement.setString(1, status);
                statement.setString(2, owner);
                statement.setString(3, proposer);
                statement.setString(4, approver);
                statement.setLong(5, adjustment);
                statement.setString(6, adjustmentCurrency);
                statement.setTimestamp(7, Timestamp.from(clock.instant()));
                statement.setObject(8, id);
                statement.setObject(9, tenant);
                statement.setLong(10, before.version());
                if (statement.executeUpdate() != 1) {
                    throw new IllegalStateException("stale exception workflow version");
                }
            }
            String actionName = action == ExceptionAction.APPROVE
                    ? "APPROVED:" + ledgerTransactionId : action.name();
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO recon_exception_action
                      (id,tenant_id,exception_id,action,actor_id,reason,
                       ledger_transaction_id,created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, UUID.randomUUID());
                statement.setObject(2, tenant);
                statement.setObject(3, id);
                statement.setString(4, actionName);
                statement.setString(5, actorId);
                statement.setString(6, reason);
                statement.setObject(7, ledgerTransactionId);
                statement.setTimestamp(8, Timestamp.from(clock.instant()));
                statement.executeUpdate();
            }
            ExceptionItem after = exception(connection, tenant, id, false);
            auditAdmin(connection, tenant, actorId, actionName, id, reason, ticketId,
                    digest(before.toString()), digest(after.toString()));
            return after;
        });
    }

    private static CurrentActors actors(Connection connection, UUID tenant, UUID id)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT proposer_id FROM recon_exception_current
                 WHERE id=? AND tenant_id=?
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, tenant);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("exception does not exist");
                }
                return new CurrentActors(result.getString(1));
            }
        }
    }

    private static ExceptionItem exception(Connection connection, UUID tenant, UUID id,
            boolean lock) throws SQLException {
        String sql = "SELECT id,match_key,status,owner_id,adjustment_minor,currency,version,updated_at "
                + "FROM recon_exception_current WHERE id=? AND tenant_id=?"
                + (lock ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            statement.setObject(2, tenant);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("exception does not exist");
                }
                return new ExceptionItem(result.getString(1), result.getString(2),
                        result.getString(3), result.getString(4), result.getLong(5),
                        result.getString(6), result.getLong(7),
                        result.getTimestamp(8).toInstant());
            }
        }
    }

    private void auditAdmin(Connection connection, UUID tenant, String actor, String action,
            UUID targetId, String reason, String ticketId, String beforeDigest,
            String afterDigest) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO financial_admin_audit
                  (id,tenant_id,actor_id,action,target_type,target_id,reason,ticket_id,
                   before_digest,after_digest,occurred_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """)) {
            statement.setObject(1, UUID.randomUUID());
            statement.setObject(2, tenant);
            statement.setString(3, actor);
            statement.setString(4, action);
            statement.setString(5, "reconciliation_exception");
            statement.setString(6, targetId.toString());
            statement.setString(7, reason);
            statement.setString(8, ticketId);
            statement.setString(9, beforeDigest);
            statement.setString(10, afterDigest);
            statement.setTimestamp(11, Timestamp.from(clock.instant()));
            statement.executeUpdate();
        }
    }

    private List<FinancialReportService.Fact> facts(UUID tenant, Instant from, Instant to) {
        return query(tenant, connection -> {
            List<FinancialReportService.Fact> values = new ArrayList<>();
            appendFacts(connection, values, tenant, from, to, """
                    SELECT id::text,'CAPTURE',captured_amount_minor,currency,updated_at
                      FROM payment_intent WHERE tenant_id=? AND captured_amount_minor>0
                       AND updated_at>=? AND updated_at<?
                    """);
            appendFacts(connection, values, tenant, from, to, """
                    SELECT id::text,'REFUND',amount_minor,currency,updated_at
                      FROM refund WHERE tenant_id=? AND state IN ('succeeded','partially_succeeded')
                       AND updated_at>=? AND updated_at<?
                    """);
            appendFacts(connection, values, tenant, from, to, """
                    SELECT id::text,'FEE',total_minor,currency,created_at
                      FROM fee_record WHERE tenant_id=? AND created_at>=? AND created_at<?
                    """);
            appendFacts(connection, values, tenant, from, to, """
                    SELECT id::text,'CHARGEBACK',amount_minor,currency,updated_at
                      FROM provider_dispute WHERE tenant_id=? AND state IN ('lost','accepted')
                       AND updated_at>=? AND updated_at<?
                    """);
            appendFacts(connection, values, tenant, from, to, """
                    SELECT id::text,'SETTLEMENT',expected_bank_minor,currency,expected_arrival
                      FROM settlement_instruction WHERE tenant_id=?
                       AND expected_arrival>=? AND expected_arrival<?
                    """);
            appendFacts(connection, values, tenant, from, to, """
                    SELECT id::text,'EXCEPTION',adjustment_minor,currency,updated_at
                      FROM recon_exception_current WHERE tenant_id=? AND status='RESOLVED'
                       AND updated_at>=? AND updated_at<?
                    """);
            return List.copyOf(values);
        });
    }

    private static void appendFacts(Connection connection,
            List<FinancialReportService.Fact> values, UUID tenant, Instant from, Instant to,
            String sql) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, tenant);
            statement.setTimestamp(2, Timestamp.from(from));
            statement.setTimestamp(3, Timestamp.from(to));
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    values.add(new FinancialReportService.Fact(result.getString(1),
                            tenant.toString(), FinancialReportService.Type.valueOf(result.getString(2)),
                            result.getLong(3), result.getString(4),
                            result.getTimestamp(5).toInstant()));
                }
            }
        }
    }

    private long claimJob(UUID tenant, String jobName, java.time.LocalDate date, String workerId,
            String manifestDigest) {
        return query(tenant, connection -> {
            Instant now = clock.instant();
            try (PreparedStatement insert = connection.prepareStatement("""
                    INSERT INTO financial_runtime_job
                      (tenant_id,job_name,business_date,state,input_manifest_sha256,
                       created_at,updated_at)
                    VALUES (?,?,?,'queued',?,?,?) ON CONFLICT DO NOTHING
                    """)) {
                insert.setObject(1, tenant);
                insert.setString(2, jobName);
                insert.setObject(3, date);
                insert.setString(4, requiredDigest(manifestDigest));
                insert.setTimestamp(5, Timestamp.from(now));
                insert.setTimestamp(6, Timestamp.from(now));
                insert.executeUpdate();
            }
            try (PreparedStatement update = connection.prepareStatement("""
                    UPDATE financial_runtime_job
                       SET state='running',lease_owner=?,lease_until=?,
                           fencing_token=fencing_token+1,updated_at=?,last_error_code=NULL
                     WHERE tenant_id=? AND job_name=? AND business_date=?
                       AND state<>'completed'
                       AND (state<>'running' OR lease_until<=?)
                       AND input_manifest_sha256=?
                    RETURNING fencing_token
                    """)) {
                update.setString(1, workerId);
                update.setTimestamp(2, Timestamp.from(now.plus(JOB_LEASE)));
                update.setTimestamp(3, Timestamp.from(now));
                update.setObject(4, tenant);
                update.setString(5, jobName);
                update.setObject(6, date);
                update.setTimestamp(7, Timestamp.from(now));
                update.setString(8, requiredDigest(manifestDigest));
                try (ResultSet result = update.executeQuery()) {
                    if (!result.next()) {
                        throw new IllegalStateException(
                                "financial job is busy, completed, or manifest-conflicted");
                    }
                    return result.getLong(1);
                }
            }
        });
    }

    private void finishJob(UUID tenant, String jobName, java.time.LocalDate date, String workerId,
            long fencingToken, String resultReference, String failureCode) {
        query(tenant, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE financial_runtime_job
                       SET state=?,result_reference=?,last_error_code=?,lease_owner=NULL,
                           lease_until=NULL,updated_at=?
                     WHERE tenant_id=? AND job_name=? AND business_date=? AND state='running'
                       AND lease_owner=? AND fencing_token=? AND lease_until>?
                    """)) {
                Instant now = clock.instant();
                statement.setString(1, failureCode == null ? "completed" : "failed");
                statement.setString(2, resultReference);
                statement.setString(3, failureCode == null ? null : safeCode(failureCode));
                statement.setTimestamp(4, Timestamp.from(now));
                statement.setObject(5, tenant);
                statement.setString(6, jobName);
                statement.setObject(7, date);
                statement.setString(8, workerId);
                statement.setLong(9, fencingToken);
                statement.setTimestamp(10, Timestamp.from(now));
                if (statement.executeUpdate() != 1) {
                    throw new IllegalStateException("stale financial job fencing token");
                }
            }
            return null;
        });
    }

    private <T> T query(UUID tenant, SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                TenantSession.setLocal(connection, tenant);
                T value = work.run(connection);
                connection.commit();
                return value;
            } catch (RuntimeException | SQLException failure) {
                TenantSession.rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw persistence("financial database operation failed", failure);
            }
        } catch (SQLException failure) {
            throw persistence("financial database is unavailable", failure);
        }
    }

    private static byte[] artifact(FinancialReportService.Report report) {
        StringBuilder value = new StringBuilder("elmpay-financial-export-v1\n");
        value.append("tenant=").append(report.tenantId()).append('\n');
        value.append("from=").append(report.from()).append('\n');
        value.append("to=").append(report.to()).append('\n');
        value.append("source_digest=").append(report.sourceDigest()).append('\n');
        value.append("signing_key_version=").append(report.signingKeyVersion()).append('\n');
        value.append("signature=").append(report.manifestSignature()).append('\n');
        report.byCurrency().entrySet().stream().sorted(java.util.Map.Entry.comparingByKey())
                .forEach(entry -> value.append(entry.getKey()).append('=')
                        .append(entry.getValue()).append('\n'));
        return value.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String provider(String value) {
        String normalized = required(value, "provider").toLowerCase(Locale.ROOT);
        if (!java.util.Set.of("wechat", "alipay", "stripe", "paypal", "apple_pay")
                .contains(normalized)) {
            throw new IllegalArgumentException("unsupported reconciliation provider");
        }
        return normalized;
    }

    private static String requiredDigest(String value) {
        String digest = required(value, "digest").toLowerCase(Locale.ROOT);
        if (!digest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("digest must be SHA-256 hex");
        }
        return digest;
    }

    private static String required(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
        return value;
    }

    private static String safeCode(String value) {
        String normalized = value.replaceAll("[^A-Za-z0-9_.-]", "_");
        return normalized.substring(0, Math.min(normalized.length(), 120));
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("JDK is missing SHA-256", unavailable);
        }
    }

    private static void bounded(int limit) {
        if (limit <= 0 || limit > 1_000) {
            throw new IllegalArgumentException("limit must be between 1 and 1000");
        }
    }

    private static IllegalStateException persistence(String message, Throwable cause) {
        return new IllegalStateException(message, cause);
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T run(Connection connection) throws SQLException;
    }

    private enum ExceptionAction { CLAIM, PROPOSE, APPROVE, REJECT }
    private record CurrentActors(String proposer) {}
}
