package com.elmpay.scheduler;

import com.elmpay.reconciliation.ReconciliationEngine;
import com.elmpay.security.CanonicalPayload;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Creates one immutable, cutoff-bound four-source fact snapshot under repeatable-read isolation.
 * Raw business references never leave the source transaction; members retain only SHA-256.
 */
public final class JdbcReconciliationFactSnapshotSource
        implements ReconciliationSchedulerJob.FactSnapshotSource {
    public static final class MissingSourceException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private MissingSourceException(String message) {
            super(message);
        }
    }
    private static final Comparator<ReconciliationEngine.Fact> FACT_ORDER = Comparator
            .comparing((ReconciliationEngine.Fact fact) -> fact.source().ordinal())
            .thenComparing(ReconciliationEngine.Fact::externalReference)
            .thenComparing(ReconciliationEngine.Fact::eventType)
            .thenComparing(ReconciliationEngine.Fact::currency)
            .thenComparingLong(ReconciliationEngine.Fact::amountMinor)
            .thenComparing(ReconciliationEngine.Fact::occurredAt)
            .thenComparing(ReconciliationEngine.Fact::sourceDigest);

    private final DataSource dataSource;
    private final Clock clock;
    private final int maximumFacts;

    public JdbcReconciliationFactSnapshotSource(DataSource dataSource, Clock clock,
            int maximumFacts) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (maximumFacts < 1 || maximumFacts > 1_000_000) {
            throw new IllegalArgumentException("maximumFacts must be 1..1000000");
        }
        this.maximumFacts = maximumFacts;
    }

    @Override
    public ReconciliationSchedulerJob.FactSnapshot snapshot(
            ReconciliationSchedulerJob.SnapshotRequest request) {
        Objects.requireNonNull(request, "request");
        if (request.cutoff().isAfter(clock.instant().plusSeconds(300))) {
            throw new IllegalArgumentException("reconciliation cutoff is in the future");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            try {
                setTenant(connection, request.tenantId());
                lockIdentity(connection, request);
                ReconciliationSchedulerJob.FactSnapshot existing = load(connection, request);
                if (existing != null) {
                    connection.commit();
                    return existing;
                }
                List<FactWithProject> sourceFacts = new ArrayList<>();
                appendBusiness(connection, request, sourceFacts);
                appendPlatform(connection, request, sourceFacts);
                appendStatement(connection, request, ReconciliationEngine.Source.PROVIDER,
                        sourceFacts);
                appendStatement(connection, request, ReconciliationEngine.Source.BANK,
                        sourceFacts);
                if (sourceFacts.isEmpty()) {
                    throw new MissingSourceException(
                            "no immutable reconciliation facts exist at the selected cutoff");
                }
                if (sourceFacts.size() > maximumFacts) {
                    throw new IllegalStateException("reconciliation snapshot exceeds its bound");
                }
                rejectAmbiguousProjects(sourceFacts);
                List<ReconciliationEngine.Fact> facts = sourceFacts.stream()
                        .map(FactWithProject::fact).sorted(FACT_ORDER).toList();
                requireEverySource(facts);
                SnapshotMaterial material = material(request, facts);
                persist(connection, request, facts, material);
                connection.commit();
                return new ReconciliationSchedulerJob.FactSnapshot(request,
                        material.sourceSetDigest(), material.manifestDigest(), facts);
            } catch (RuntimeException | SQLException failure) {
                rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new IllegalStateException("reconciliation snapshot database failure",
                        failure);
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("reconciliation snapshot database is unavailable",
                    failure);
        }
    }

    private void appendBusiness(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request, List<FactWithProject> facts)
            throws SQLException {
        String sql = """
                SELECT e.project_id,
                       encode(sha256(convert_to(p.external_reference,'UTF8')),'hex') AS reference,
                       CASE e.event_type WHEN 'payment_intent.captured' THEN 'CAPTURE'
                                         ELSE 'REFUND' END AS event_type,
                       (e.payload->>'amount_minor')::bigint AS amount_minor,
                       e.payload->>'currency' AS currency,e.occurred_at,
                       encode(sha256(convert_to(concat_ws(E'\\x1f','outbox',e.id::text,
                         e.event_type,e.event_version::text,e.aggregate_revision::text,
                         e.payload::text,
                         to_char(e.occurred_at AT TIME ZONE 'UTC',
                           'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                         to_char(e.recorded_at AT TIME ZONE 'UTC',
                           'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),'UTF8')),'hex') AS source_digest
                  FROM outbox_event e
                  LEFT JOIN refund r ON e.event_type='refund.succeeded'
                    AND r.tenant_id=e.tenant_id AND r.project_id=e.project_id
                    AND r.id=e.aggregate_id
                  JOIN payment_intent p ON p.tenant_id=e.tenant_id
                    AND p.project_id=e.project_id
                    AND p.id=CASE WHEN e.event_type='payment_intent.captured'
                                  THEN e.aggregate_id ELSE r.payment_intent_id END
                 WHERE e.tenant_id=? AND e.event_type IN
                       ('payment_intent.captured','refund.succeeded')
                   AND e.occurred_at>=? AND e.occurred_at<? AND e.recorded_at<=?
                   AND e.payload->>'provider'=?
                   AND e.payload->>'currency'=p.currency
                   AND (e.event_type<>'payment_intent.captured'
                        OR e.payload->>'business_order_digest'=
                           encode(sha256(convert_to(p.external_reference,'UTF8')),'hex'))
                 ORDER BY e.sequence_no
                """;
        queryFacts(connection, request, ReconciliationEngine.Source.BUSINESS, sql, facts);
    }

    private void appendPlatform(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request, List<FactWithProject> facts)
            throws SQLException {
        String sql = """
                SELECT e.project_id,
                       encode(sha256(convert_to(p.external_reference,'UTF8')),'hex') AS reference,
                       CASE e.event_type WHEN 'payment_intent.captured' THEN 'CAPTURE'
                                         ELSE 'REFUND' END AS event_type,
                       sum(le.amount_minor) FILTER (WHERE le.direction='debit') AS amount_minor,
                       min(le.currency) AS currency,e.occurred_at,
                       encode(sha256(convert_to(concat_ws(E'\\x1f','ledger',lt.id::text,
                         lt.request_hash,(sum(le.amount_minor) FILTER
                           (WHERE le.direction='debit'))::text,
                         min(le.currency)::text,
                         to_char(e.occurred_at AT TIME ZONE 'UTC',
                           'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),'UTF8')),'hex') AS source_digest
                  FROM outbox_event e
                  LEFT JOIN refund r ON e.event_type='refund.succeeded'
                    AND r.tenant_id=e.tenant_id AND r.project_id=e.project_id
                    AND r.id=e.aggregate_id
                  JOIN payment_intent p ON p.tenant_id=e.tenant_id
                    AND p.project_id=e.project_id
                    AND p.id=CASE WHEN e.event_type='payment_intent.captured'
                                  THEN e.aggregate_id ELSE r.payment_intent_id END
                  JOIN ledger_transaction lt ON lt.tenant_id=e.tenant_id
                    AND lt.source_id=concat(e.event_type,':',e.aggregate_id::text,':',
                                            e.aggregate_revision::text)
                    AND lt.source_kind=CASE WHEN e.event_type='payment_intent.captured'
                                            THEN 'payment' ELSE 'refund' END
                  JOIN ledger_entry le ON le.tenant_id=lt.tenant_id
                    AND le.transaction_id=lt.id
                 WHERE e.tenant_id=? AND e.event_type IN
                       ('payment_intent.captured','refund.succeeded')
                   AND e.occurred_at>=? AND e.occurred_at<? AND e.recorded_at<=?
                   AND lt.posted_at<=? AND e.payload->>'provider'=?
                 GROUP BY e.project_id,p.external_reference,e.event_type,e.occurred_at,
                          e.sequence_no,lt.id,lt.request_hash
                HAVING count(DISTINCT le.currency)=1
                   AND sum(le.amount_minor) FILTER (WHERE le.direction='debit') > 0
                   AND sum(le.amount_minor) FILTER (WHERE le.direction='debit') =
                       sum(le.amount_minor) FILTER (WHERE le.direction='credit')
                 ORDER BY e.sequence_no
                """;
        queryFacts(connection, request, ReconciliationEngine.Source.PLATFORM, sql, facts);
    }

    private void appendStatement(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request,
            ReconciliationEngine.Source source, List<FactWithProject> facts) throws SQLException {
        String sql = """
                SELECT NULL::uuid AS project_id,
                       encode(sha256(convert_to(sr.external_reference,'UTF8')),'hex') AS reference,
                       sr.event_type,sr.amount_minor,sr.currency,sr.occurred_at,
                       encode(sha256(convert_to(concat_ws(E'\\x1f',sf.content_sha256,
                         sf.parser_version,sr.row_number::text,sr.external_reference,
                         sr.amount_minor::text,
                         sr.currency,sr.event_type,
                         to_char(sr.occurred_at AT TIME ZONE 'UTC',
                           'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),'UTF8')),'hex')
                         AS source_digest
                  FROM statement_file sf
                  JOIN statement_row sr ON sr.tenant_id=sf.tenant_id AND sr.file_id=sf.id
                 WHERE sf.tenant_id=? AND sf.kind=? AND sf.reconciliation_provider=?
                   AND sf.ingested_at<=?
                   AND NOT EXISTS (
                       SELECT 1 FROM statement_file newer
                        WHERE newer.tenant_id=sf.tenant_id AND newer.kind=sf.kind
                          AND newer.source=sf.source
                          AND newer.content_sha256=sf.content_sha256
                          AND newer.ingested_at<=?
                          AND (newer.ingested_at,newer.id)>(sf.ingested_at,sf.id))
                   AND sr.occurred_at>=? AND sr.occurred_at<?
                 ORDER BY sf.ingested_at,sf.id,sr.row_number
                """;
        Instant start = request.businessDate().atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant end = request.businessDate().plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, request.tenantId());
            statement.setString(2, source.name());
            statement.setString(3, request.provider());
            statement.setTimestamp(4, Timestamp.from(request.cutoff()));
            statement.setTimestamp(5, Timestamp.from(request.cutoff()));
            statement.setTimestamp(6, Timestamp.from(start));
            statement.setTimestamp(7, Timestamp.from(end));
            statement.setMaxRows(remaining(facts));
            collect(statement, request.tenantId(), source, facts);
            requireBounded(facts);
        }
    }

    private void queryFacts(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request,
            ReconciliationEngine.Source source, String sql, List<FactWithProject> facts)
            throws SQLException {
        Instant start = request.businessDate().atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant end = request.businessDate().plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, request.tenantId());
            statement.setTimestamp(2, Timestamp.from(start));
            statement.setTimestamp(3, Timestamp.from(end));
            statement.setTimestamp(4, Timestamp.from(request.cutoff()));
            int providerIndex = 5;
            if (source == ReconciliationEngine.Source.PLATFORM) {
                statement.setTimestamp(5, Timestamp.from(request.cutoff()));
                providerIndex = 6;
            }
            statement.setString(providerIndex, request.provider());
            statement.setMaxRows(remaining(facts));
            collect(statement, request.tenantId(), source, facts);
            requireBounded(facts);
        }
    }

    private int remaining(List<FactWithProject> facts) {
        return Math.addExact(Math.subtractExact(maximumFacts, facts.size()), 1);
    }

    private void requireBounded(List<FactWithProject> facts) {
        if (facts.size() > maximumFacts) {
            throw new IllegalStateException("reconciliation snapshot exceeds its bound");
        }
    }

    private static void collect(PreparedStatement statement, UUID tenant,
            ReconciliationEngine.Source source, List<FactWithProject> facts) throws SQLException {
        try (ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                UUID project = result.getObject("project_id", UUID.class);
                facts.add(new FactWithProject(project, new ReconciliationEngine.Fact(source,
                        tenant.toString(), result.getString("reference"),
                        result.getString("event_type"), result.getLong("amount_minor"),
                        result.getString("currency"), result.getTimestamp("occurred_at").toInstant(),
                        result.getString("source_digest"))));
            }
        }
    }

    private static void rejectAmbiguousProjects(List<FactWithProject> facts) {
        Map<String, UUID> projectsByBusinessKey = new java.util.HashMap<>();
        for (FactWithProject value : facts) {
            if (value.projectId() == null) {
                continue;
            }
            String key = value.fact().externalReference() + ':' + value.fact().eventType();
            UUID existing = projectsByBusinessKey.putIfAbsent(key, value.projectId());
            if (existing != null && !existing.equals(value.projectId())) {
                throw new IllegalStateException(
                        "business reference is ambiguous across projects for this tenant");
            }
        }
    }

    private static void requireEverySource(List<ReconciliationEngine.Fact> facts) {
        java.util.EnumSet<ReconciliationEngine.Source> present = java.util.EnumSet.noneOf(
                ReconciliationEngine.Source.class);
        for (ReconciliationEngine.Fact fact : facts) {
            present.add(fact.source());
        }
        if (!present.equals(java.util.EnumSet.allOf(ReconciliationEngine.Source.class))) {
            throw new MissingSourceException(
                    "reconciliation snapshot is missing a required independent source");
        }
    }

    private static SnapshotMaterial material(ReconciliationSchedulerJob.SnapshotRequest request,
            List<ReconciliationEngine.Fact> facts) {
        Map<ReconciliationEngine.Source, List<Map<String, Object>>> sourceRows =
                new EnumMap<>(ReconciliationEngine.Source.class);
        for (ReconciliationEngine.Source source : ReconciliationEngine.Source.values()) {
            sourceRows.put(source, new ArrayList<>());
        }
        for (ReconciliationEngine.Fact fact : facts) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("amount_minor", fact.amountMinor());
            row.put("currency", fact.currency());
            row.put("event_type", fact.eventType());
            row.put("external_reference_sha256", fact.externalReference());
            row.put("occurred_at", fact.occurredAt());
            row.put("source_record_sha256", fact.sourceDigest());
            sourceRows.get(fact.source()).add(Map.copyOf(row));
        }
        Map<String, Object> sources = new LinkedHashMap<>();
        for (ReconciliationEngine.Source source : ReconciliationEngine.Source.values()) {
            List<Map<String, Object>> rows = List.copyOf(sourceRows.get(source));
            Map<String, Object> sourceManifest = new LinkedHashMap<>();
            sourceManifest.put("count", rows.size());
            sourceManifest.put("sha256", CanonicalPayload.sha256Hex(rows));
            sources.put(source.name(), Map.copyOf(sourceManifest));
        }
        String sourceSetDigest = CanonicalPayload.sha256Hex(sources);
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("business_date", request.businessDate().toString());
        manifest.put("cutoff_at", request.cutoff());
        manifest.put("provider", request.provider());
        manifest.put("schema", "elmpay.reconciliation.fact-snapshot.v1");
        manifest.put("source_set_sha256", sourceSetDigest);
        manifest.put("sources", Map.copyOf(sources));
        manifest.put("tenant_id", request.tenantId());
        byte[] canonical = CanonicalPayload.encode(manifest);
        return new SnapshotMaterial(sourceSetDigest,
                CanonicalPayload.sha256Hex(manifest),
                new String(canonical, StandardCharsets.UTF_8), sourceRows);
    }

    private static void persist(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request,
            List<ReconciliationEngine.Fact> facts, SnapshotMaterial material) throws SQLException {
        UUID id = UUID.randomUUID();
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO reconciliation_fact_snapshot
                  (id,tenant_id,provider,business_date,cutoff_at,source_set_sha256,
                   input_manifest_sha256,canonical_manifest,business_count,platform_count,
                   provider_count,bank_count,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,clock_timestamp())
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, request.tenantId());
            statement.setString(3, request.provider());
            statement.setObject(4, request.businessDate());
            statement.setTimestamp(5, Timestamp.from(request.cutoff()));
            statement.setString(6, material.sourceSetDigest());
            statement.setString(7, material.manifestDigest());
            statement.setString(8, material.canonicalManifest());
            statement.setInt(9, material.rows().get(ReconciliationEngine.Source.BUSINESS).size());
            statement.setInt(10, material.rows().get(ReconciliationEngine.Source.PLATFORM).size());
            statement.setInt(11, material.rows().get(ReconciliationEngine.Source.PROVIDER).size());
            statement.setInt(12, material.rows().get(ReconciliationEngine.Source.BANK).size());
            statement.executeUpdate();
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO reconciliation_fact_snapshot_member
                  (snapshot_id,tenant_id,ordinal,source,external_reference_sha256,event_type,
                   amount_minor,currency,occurred_at,source_record_sha256)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """)) {
            for (int index = 0; index < facts.size(); index++) {
                ReconciliationEngine.Fact fact = facts.get(index);
                statement.setObject(1, id);
                statement.setObject(2, request.tenantId());
                statement.setInt(3, index);
                statement.setString(4, fact.source().name());
                statement.setString(5, fact.externalReference());
                statement.setString(6, fact.eventType());
                statement.setLong(7, fact.amountMinor());
                statement.setString(8, fact.currency());
                statement.setTimestamp(9, Timestamp.from(fact.occurredAt()));
                statement.setString(10, fact.sourceDigest());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private ReconciliationSchedulerJob.FactSnapshot load(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request) throws SQLException {
        UUID snapshotId;
        String sourceSet;
        String manifestDigest;
        String canonicalManifest;
        int businessCount;
        int platformCount;
        int providerCount;
        int bankCount;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id,source_set_sha256,input_manifest_sha256,canonical_manifest,
                       business_count,platform_count,provider_count,bank_count
                  FROM reconciliation_fact_snapshot
                 WHERE tenant_id=? AND provider=? AND business_date=? AND cutoff_at=?
                """)) {
            statement.setObject(1, request.tenantId());
            statement.setString(2, request.provider());
            statement.setObject(3, request.businessDate());
            statement.setTimestamp(4, Timestamp.from(request.cutoff()));
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                snapshotId = result.getObject(1, UUID.class);
                sourceSet = result.getString(2);
                manifestDigest = result.getString(3);
                canonicalManifest = result.getString(4);
                businessCount = result.getInt(5);
                platformCount = result.getInt(6);
                providerCount = result.getInt(7);
                bankCount = result.getInt(8);
                if (result.next()) {
                    throw new SQLException("snapshot identity is not unique");
                }
            }
        }
        if (!sha256(canonicalManifest).equals(manifestDigest)) {
            throw new IllegalStateException("stored reconciliation manifest digest mismatch");
        }
        List<ReconciliationEngine.Fact> facts = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT source,external_reference_sha256,event_type,amount_minor,currency,
                       occurred_at,source_record_sha256
                  FROM reconciliation_fact_snapshot_member
                 WHERE snapshot_id=? AND tenant_id=? ORDER BY ordinal
                """)) {
            statement.setObject(1, snapshotId);
            statement.setObject(2, request.tenantId());
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    if (facts.size() >= maximumFacts) {
                        throw new IllegalStateException(
                                "stored reconciliation snapshot exceeds its bound");
                    }
                    facts.add(new ReconciliationEngine.Fact(
                            ReconciliationEngine.Source.valueOf(result.getString(1)),
                            request.tenantId().toString(), result.getString(2), result.getString(3),
                            result.getLong(4), result.getString(5),
                            result.getTimestamp(6).toInstant(), result.getString(7)));
                }
            }
        }
        if (facts.isEmpty()) {
            throw new IllegalStateException("stored reconciliation snapshot has no members");
        }
        requireEverySource(facts);
        SnapshotMaterial recomputed = material(request, List.copyOf(facts));
        if (businessCount != recomputed.rows().get(ReconciliationEngine.Source.BUSINESS).size()
                || platformCount != recomputed.rows().get(
                        ReconciliationEngine.Source.PLATFORM).size()
                || providerCount != recomputed.rows().get(
                        ReconciliationEngine.Source.PROVIDER).size()
                || bankCount != recomputed.rows().get(ReconciliationEngine.Source.BANK).size()
                || !MessageDigest.isEqual(sourceSet.getBytes(StandardCharsets.US_ASCII),
                    recomputed.sourceSetDigest().getBytes(StandardCharsets.US_ASCII))
                || !MessageDigest.isEqual(manifestDigest.getBytes(StandardCharsets.US_ASCII),
                    recomputed.manifestDigest().getBytes(StandardCharsets.US_ASCII))
                || !MessageDigest.isEqual(canonicalManifest.getBytes(StandardCharsets.UTF_8),
                    recomputed.canonicalManifest().getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalStateException("stored reconciliation snapshot is internally inconsistent");
        }
        return new ReconciliationSchedulerJob.FactSnapshot(request, sourceSet, manifestDigest,
                facts);
    }

    private static void lockIdentity(Connection connection,
            ReconciliationSchedulerJob.SnapshotRequest request) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")) {
            statement.setString(1, request.tenantId() + ":" + request.provider() + ":"
                    + request.businessDate() + ":" + request.cutoff());
            statement.execute();
        }
    }

    private static void setTenant(Connection connection, UUID tenant) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenant.toString());
            statement.execute();
        }
    }

    private static String sha256(String value) {
        return hex(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void rollback(Connection connection, Exception failure) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            failure.addSuppressed(rollbackFailure);
        }
    }

    private record FactWithProject(UUID projectId, ReconciliationEngine.Fact fact) {}

    private record SnapshotMaterial(String sourceSetDigest, String manifestDigest,
            String canonicalManifest,
            Map<ReconciliationEngine.Source, List<Map<String, Object>>> rows) {}
}
