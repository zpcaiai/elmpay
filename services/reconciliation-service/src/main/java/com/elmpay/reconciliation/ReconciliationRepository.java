package com.elmpay.reconciliation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.time.Clock;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import javax.sql.DataSource;

/** JDBC persistence for reproducible runs, append-only exception actions and signed exports. */
public final class ReconciliationRepository {
    private static final Set<String> PROVIDERS = Set.of(
            "wechat", "alipay", "stripe", "paypal", "apple_pay");

    private final DataSource dataSource;
    private final Clock clock;

    public ReconciliationRepository(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.clock = Objects.requireNonNull(clock);
    }

    /**
     * Stores the generated run using the canonical recon_run identity tuple.
     * A duplicate source returns the existing durable run id after verifying the
     * immutable input manifest rather than attempting to write duplicate matches.
     */
    public String saveRun(ReconciliationEngine.Run run, String provider, LocalDate businessDate,
                          String sourceFileDigest, String inputManifestDigest) throws SQLException {
        Objects.requireNonNull(run, "run");
        UUID tenant = TenantSession.tenant(run.tenantId());
        UUID proposedRunId = UUID.fromString(run.id());
        String normalizedProvider = normalizedProvider(provider);
        Objects.requireNonNull(businessDate, "businessDate");
        requiredDigest(sourceFileDigest, "sourceFileDigest");
        requiredDigest(inputManifestDigest, "inputManifestDigest");

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                TenantSession.setLocal(connection, tenant);
                Savepoint insertion = connection.setSavepoint("recon_run_insert");
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO recon_run
                          (id,tenant_id,business_date,provider,source_file_digest,state,
                           started_at,completed_at,cutoff_at,input_manifest_sha256)
                        VALUES (?,?,?,?,?,'completed',?,?,?,?)
                        """)) {
                    statement.setObject(1, proposedRunId);
                    statement.setObject(2, tenant);
                    statement.setString(3, businessDate.toString());
                    statement.setString(4, normalizedProvider);
                    statement.setString(5, sourceFileDigest);
                    statement.setTimestamp(6, java.sql.Timestamp.from(clock.instant()));
                    statement.setTimestamp(7, java.sql.Timestamp.from(clock.instant()));
                    statement.setTimestamp(8, java.sql.Timestamp.from(run.cutoff()));
                    statement.setString(9, inputManifestDigest);
                    statement.executeUpdate();
                    connection.releaseSavepoint(insertion);
                } catch (SQLException duplicate) {
                    TenantSession.rollbackUniqueConflict(connection, insertion, duplicate);
                    String existing = existingRun(connection, tenant, normalizedProvider,
                            businessDate, sourceFileDigest, inputManifestDigest, run.cutoff());
                    connection.commit();
                    return existing;
                }

                List<ExceptionSeed> exceptionSeeds = new ArrayList<>();
                try (PreparedStatement match = connection.prepareStatement("""
                        INSERT INTO recon_match
                          (id,tenant_id,run_id,match_key,outcome,source_totals_json,created_at)
                        VALUES (?,?,?,?,?,?,?)
                        """)) {
                    for (ReconciliationEngine.Match value : run.matches()) {
                        UUID matchId = UUID.randomUUID();
                        match.setObject(1, matchId);
                        match.setObject(2, tenant);
                        match.setObject(3, proposedRunId);
                        match.setString(4, value.key());
                        match.setString(5, value.outcome().name());
                        match.setString(6, canonicalTotals(value.totals()));
                        match.setTimestamp(7, java.sql.Timestamp.from(clock.instant()));
                        match.addBatch();
                        if (value.outcome() != ReconciliationEngine.Outcome.MATCHED) {
                            exceptionSeeds.add(new ExceptionSeed(UUID.randomUUID(), matchId,
                                    value.key(), value.outcome().name()));
                        }
                    }
                    match.executeBatch();
                }
                saveExceptionSeeds(connection, tenant, proposedRunId, exceptionSeeds);
                connection.commit();
                return proposedRunId.toString();
            } catch (RuntimeException | SQLException failure) {
                TenantSession.rollback(connection, failure);
                throw failure;
            }
        }
    }

    private void saveExceptionSeeds(Connection connection, UUID tenant, UUID runId,
            List<ExceptionSeed> seeds) throws SQLException {
        try (PreparedStatement current = connection.prepareStatement("""
                INSERT INTO recon_exception_current
                  (id,tenant_id,match_key,status,adjustment_minor,version,updated_at)
                VALUES (?, ?, ?, 'OPEN', 0, 1, ?)
                """);
             PreparedStatement action = connection.prepareStatement("""
                INSERT INTO recon_exception_action
                  (id,tenant_id,exception_id,action,actor_id,reason,created_at)
                VALUES (?, ?, ?, 'OPENED', 'reconciliation-engine', ?, ?)
                """);
             PreparedStatement origin = connection.prepareStatement("""
                INSERT INTO recon_exception_origin
                  (exception_id,tenant_id,run_id,match_id,created_at)
                VALUES (?, ?, ?, ?, ?)
                """)) {
            for (ExceptionSeed seed : seeds) {
                java.sql.Timestamp now = java.sql.Timestamp.from(clock.instant());
                current.setObject(1, seed.exceptionId());
                current.setObject(2, tenant);
                current.setString(3, seed.matchKey());
                current.setTimestamp(4, now);
                current.addBatch();

                action.setObject(1, UUID.randomUUID());
                action.setObject(2, tenant);
                action.setObject(3, seed.exceptionId());
                action.setString(4, "reconciliation outcome: " + seed.outcome());
                action.setTimestamp(5, now);
                action.addBatch();

                origin.setObject(1, seed.exceptionId());
                origin.setObject(2, tenant);
                origin.setObject(3, runId);
                origin.setObject(4, seed.matchId());
                origin.setTimestamp(5, now);
                origin.addBatch();
            }
            current.executeBatch();
            action.executeBatch();
            origin.executeBatch();
        }
    }

    /** Retained as a fail-closed compatibility overload. */
    public void saveRun(ReconciliationEngine.Run run, String inputManifestDigest) {
        throw new IllegalArgumentException(
                "provider, businessDate and sourceFileDigest are required for canonical reconciliation identity");
    }

    public void saveTicket(ExceptionWorkflow.Ticket ticket) throws SQLException {
        ExceptionWorkflow.Audit latest = ticket.history().getLast();
        UUID tenant = TenantSession.tenant(ticket.tenantId());
        UUID ticketId = UUID.fromString(ticket.id());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                TenantSession.setLocal(connection, tenant);
                try (PreparedStatement current = connection.prepareStatement("""
                        INSERT INTO recon_exception_current
                          (id,tenant_id,match_key,status,owner_id,proposer_id,approver_id,
                           adjustment_minor,currency,version,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT (id,tenant_id) DO UPDATE SET
                          status=EXCLUDED.status, owner_id=EXCLUDED.owner_id,
                          proposer_id=EXCLUDED.proposer_id, approver_id=EXCLUDED.approver_id,
                          adjustment_minor=EXCLUDED.adjustment_minor, currency=EXCLUDED.currency,
                          version=EXCLUDED.version, updated_at=EXCLUDED.updated_at
                        WHERE recon_exception_current.version < EXCLUDED.version
                        """)) {
                    current.setObject(1, ticketId);
                    current.setObject(2, tenant);
                    current.setString(3, ticket.matchKey());
                    current.setString(4, ticket.status().name());
                    current.setString(5, ticket.owner());
                    current.setString(6, ticket.proposer());
                    current.setString(7, ticket.approver());
                    current.setLong(8, ticket.adjustmentMinor());
                    current.setString(9, ticket.currency());
                    current.setLong(10, ticket.version());
                    current.setTimestamp(11, java.sql.Timestamp.from(clock.instant()));
                    if (current.executeUpdate() != 1) {
                        throw new IllegalStateException("stale exception workflow version");
                    }
                }
                try (PreparedStatement action = connection.prepareStatement("""
                        INSERT INTO recon_exception_action
                          (id,tenant_id,exception_id,action,actor_id,reason,
                           ledger_transaction_id,created_at)
                        VALUES (?,?,?,?,?,?,?,?)
                        """)) {
                    action.setObject(1, UUID.randomUUID());
                    action.setObject(2, tenant);
                    action.setObject(3, ticketId);
                    action.setString(4, latest.action());
                    action.setString(5, latest.actor());
                    action.setString(6, latest.reason());
                    if (latest.action().startsWith("APPROVED:")) {
                        action.setObject(7, UUID.fromString(
                                latest.action().substring("APPROVED:".length())));
                    } else {
                        action.setNull(7, java.sql.Types.OTHER);
                    }
                    action.setTimestamp(8, java.sql.Timestamp.from(latest.at()));
                    action.executeUpdate();
                }
                connection.commit();
            } catch (RuntimeException | SQLException failure) {
                TenantSession.rollback(connection, failure);
                throw failure;
            }
        }
    }

    public String saveExport(FinancialReportService.Report report, byte[] artifact)
            throws SQLException {
        String objectDigest = digest(artifact);
        UUID id = UUID.randomUUID();
        UUID tenant = TenantSession.tenant(report.tenantId());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                TenantSession.setLocal(connection, tenant);
                Savepoint insertion = connection.setSavepoint("financial_export_insert");
                try (PreparedStatement export = connection.prepareStatement("""
                        INSERT INTO financial_export
                          (id,tenant_id,period_start,period_end,source_digest,
                           signing_key_version,manifest_signature,object_digest,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """)) {
                    export.setObject(1, id);
                    export.setObject(2, tenant);
                    export.setTimestamp(3, java.sql.Timestamp.from(report.from()));
                    export.setTimestamp(4, java.sql.Timestamp.from(report.to()));
                    export.setString(5, report.sourceDigest());
                    export.setString(6, report.signingKeyVersion());
                    export.setString(7, report.manifestSignature());
                    export.setString(8, objectDigest);
                    export.setTimestamp(9, java.sql.Timestamp.from(clock.instant()));
                    export.executeUpdate();
                    connection.releaseSavepoint(insertion);
                } catch (SQLException duplicate) {
                    TenantSession.rollbackUniqueConflict(connection, insertion, duplicate);
                    try (PreparedStatement existing = connection.prepareStatement("""
                            SELECT signing_key_version,manifest_signature,object_digest
                              FROM financial_export
                             WHERE tenant_id=? AND period_start=? AND period_end=?
                               AND source_digest=?
                            """)) {
                        existing.setObject(1, tenant);
                        existing.setTimestamp(2, java.sql.Timestamp.from(report.from()));
                        existing.setTimestamp(3, java.sql.Timestamp.from(report.to()));
                        existing.setString(4, report.sourceDigest());
                        try (ResultSet result = existing.executeQuery()) {
                            if (!result.next()
                                    || !MessageDigest.isEqual(bytes(report.signingKeyVersion()),
                                            bytes(result.getString(1)))
                                    || !MessageDigest.isEqual(bytes(report.manifestSignature()),
                                            bytes(result.getString(2)))
                                    || !MessageDigest.isEqual(bytes(objectDigest),
                                            bytes(result.getString(3)))) {
                                throw new IllegalStateException(
                                        "financial export identity was reused with different bytes");
                            }
                        }
                    }
                }
                connection.commit();
            } catch (RuntimeException | SQLException failure) {
                TenantSession.rollback(connection, failure);
                throw failure;
            }
        }
        return objectDigest;
    }

    private static String existingRun(Connection connection, UUID tenant, String provider,
                                      LocalDate businessDate, String sourceFileDigest,
                                      String expectedManifest, java.time.Instant expectedCutoff)
            throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("""
                SELECT id,input_manifest_sha256,cutoff_at
                  FROM recon_run
                 WHERE tenant_id=? AND provider=? AND business_date=? AND source_file_digest=?
                """)) {
            query.setObject(1, tenant);
            query.setString(2, provider);
            query.setString(3, businessDate.toString());
            query.setString(4, sourceFileDigest);
            try (ResultSet result = query.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("unique conflict without an existing run");
                }
                java.time.Instant storedCutoff = result.getTimestamp(3).toInstant();
                if (!MessageDigest.isEqual(bytes(expectedManifest), bytes(result.getString(2)))
                        || !storedCutoff.equals(expectedCutoff)) {
                    throw new IllegalStateException(
                            "reconciliation source identity reused with different immutable inputs");
                }
                return result.getString(1);
            }
        }
    }

    private static String normalizedProvider(String provider) {
        if (provider == null) {
            throw new IllegalArgumentException("provider is required");
        }
        String normalized = provider.toLowerCase(Locale.ROOT);
        if (!PROVIDERS.contains(normalized)) {
            throw new IllegalArgumentException("unsupported reconciliation provider");
        }
        return normalized;
    }

    private static void requiredDigest(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
    }

    private static String canonicalTotals(Map<ReconciliationEngine.Source, Long> totals) {
        StringBuilder value = new StringBuilder("{");
        totals.entrySet().stream().sorted(Map.Entry.comparingByKey(Comparator.naturalOrder()))
                .forEach(entry -> {
                    if (value.length() > 1) {
                        value.append(',');
                    }
                    value.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
                });
        return value.append('}').toString();
    }

    private static String digest(byte[] value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private record ExceptionSeed(UUID exceptionId, UUID matchId, String matchKey,
            String outcome) {}
}
