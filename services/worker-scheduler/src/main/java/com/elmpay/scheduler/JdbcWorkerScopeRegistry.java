package com.elmpay.scheduler;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** Reads the bounded active tenant/project work set from the payment fact plane. */
public final class JdbcWorkerScopeRegistry {
    private static final Map<String, List<String>> REQUIRED_SCHEMA = Map.ofEntries(
            Map.entry("tenant", List.of("id", "status")),
            Map.entry("project", List.of("id", "tenant_id", "status")),
            Map.entry("outbox_event", List.of("id", "tenant_id", "project_id", "sequence_no",
                    "event_type", "event_version", "aggregate_revision", "payload",
                    "occurred_at", "recorded_at", "published_at", "next_attempt_at",
                    "lease_owner", "lease_until", "fencing_token", "delivery_attempts")),
            Map.entry("consumer_event_inbox", List.of("tenant_id", "consumer_name",
                    "source_event_id", "payload_sha256", "state", "lease_owner", "lease_until",
                    "fencing_token")),
            Map.entry("payment_projection_checkpoint", List.of("tenant_id", "project_id",
                    "projector_name", "last_sequence_no", "generation")),
            Map.entry("billing_subscription", List.of("id", "tenant_id", "project_id", "state")),
            Map.entry("provider_account", List.of("id", "tenant_id", "project_id", "provider",
                    "environment", "status")),
            Map.entry("provider_capability", List.of("tenant_id", "provider_account_id",
                    "method", "currencies")),
            Map.entry("payment_intent", List.of("id", "tenant_id", "project_id",
                    "external_reference", "currency")),
            Map.entry("refund", List.of("id", "tenant_id", "project_id",
                    "payment_intent_id")),
            Map.entry("tenant_archive_fact", List.of("tenant_id", "occurred_at",
                    "source_record_digest")),
            Map.entry("ledger_transaction", List.of("id", "tenant_id", "source_kind",
                    "source_id", "request_hash", "posted_at")),
            Map.entry("ledger_entry", List.of("tenant_id", "transaction_id", "direction",
                    "amount_minor", "currency")),
            Map.entry("statement_file", List.of("id", "tenant_id", "kind", "source",
                    "parser_version", "content_sha256", "reconciliation_provider",
                    "ingested_at")),
            Map.entry("statement_row", List.of("tenant_id", "file_id", "row_number",
                    "external_reference", "amount_minor", "currency", "event_type",
                    "occurred_at")),
            Map.entry("reconciliation_fact_snapshot", List.of("id", "tenant_id", "provider",
                    "business_date", "cutoff_at", "source_set_sha256",
                    "input_manifest_sha256")),
            Map.entry("reconciliation_fact_snapshot_member", List.of("snapshot_id", "tenant_id",
                    "ordinal", "source", "source_record_sha256")),
            Map.entry("reconciliation_schedule_cursor", List.of("tenant_id", "provider",
                    "next_business_date", "fencing_token", "updated_at")),
            Map.entry("financial_runtime_job", List.of("tenant_id", "job_name", "business_date",
                    "state", "lease_owner", "lease_until", "fencing_token",
                    "input_manifest_sha256", "result_reference", "cutoff_at",
                    "source_set_sha256")),
            Map.entry("recon_run", List.of("id", "tenant_id", "business_date", "provider",
                    "source_file_digest", "cutoff_at", "input_manifest_sha256")),
            Map.entry("recon_match", List.of("tenant_id", "run_id", "outcome")),
            Map.entry("recon_exception_current", List.of("id", "tenant_id", "match_key",
                    "status", "version")),
            Map.entry("recon_exception_action", List.of("tenant_id", "exception_id", "action")),
            Map.entry("recon_exception_origin", List.of("exception_id", "tenant_id", "run_id",
                    "match_id")));

    public record Scope(UUID tenantId, UUID projectId) {
        public Scope {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
        }
    }

    private static final String ACTIVE_SCOPES_SQL = """
            SELECT tenant_id, project_id
              FROM public.elmpay_active_worker_scopes(?::uuid, ?::uuid, ?)
            """;

    private final DataSource dataSource;

    public JdbcWorkerScopeRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public List<Scope> activeScopes(int maximum) {
        return activeScopes(maximum, null);
    }

    public List<Scope> activeScopes(int maximum, Scope after) {
        if (maximum < 1 || maximum > 10_000) {
            throw new IllegalArgumentException("maximum scopes must be 1..10000");
        }
        List<Scope> page = query(maximum, after);
        if (page.isEmpty() && after != null) {
            return query(maximum, null);
        }
        return page;
    }

    private List<Scope> query(int maximum, Scope after) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            try (PreparedStatement statement = connection.prepareStatement(ACTIVE_SCOPES_SQL)) {
                if (after == null) {
                    statement.setObject(1, null);
                    statement.setObject(2, null);
                } else {
                    statement.setObject(1, after.tenantId());
                    statement.setObject(2, after.projectId());
                }
                statement.setInt(3, maximum);
                List<Scope> scopes = new ArrayList<>();
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        scopes.add(new Scope(result.getObject("tenant_id", UUID.class),
                                result.getObject("project_id", UUID.class)));
                    }
                }
                return List.copyOf(scopes);
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("active worker scopes cannot be loaded", failure);
        }
    }

    public void verifyRequiredSchema() {
        try (Connection connection = dataSource.getConnection()) {
            requireRestrictedRole(connection);
            requireScopeDiscoveryFunction(connection);
            for (Map.Entry<String, List<String>> table : REQUIRED_SCHEMA.entrySet()) {
                requireTable(connection, table.getKey());
                for (String column : table.getValue()) {
                    requireColumn(connection, table.getKey(), column);
                }
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("worker schema readiness check failed", failure);
        }
    }

    private static void requireRestrictedRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT NOT rolsuper AND NOT rolbypassrls
                  FROM pg_roles
                 WHERE rolname = current_user
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1)) {
                throw new IllegalStateException(
                        "worker database role must not be superuser or bypass RLS");
            }
        }
    }

    private static void requireScopeDiscoveryFunction(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT CASE
                         WHEN to_regprocedure(
                           'public.elmpay_active_worker_scopes(uuid,uuid,integer)') IS NULL
                         THEN false
                         ELSE has_function_privilege(current_user,
                           to_regprocedure(
                             'public.elmpay_active_worker_scopes(uuid,uuid,integer)'),
                           'EXECUTE')
                       END
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1)) {
                throw new IllegalStateException(
                        "worker role lacks bounded active-scope discovery capability");
            }
        }
    }

    private static void requireTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT to_regclass(?) IS NOT NULL")) {
            statement.setString(1, table);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1)) {
                    throw new IllegalStateException(
                            "required worker schema is missing table " + table);
                }
            }
        }
    }

    private static void requireColumn(Connection connection, String table, String column)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns
                     WHERE table_schema = current_schema()
                       AND table_name = ? AND column_name = ?
                )
                """)) {
            statement.setString(1, table);
            statement.setString(2, column);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1)) {
                    throw new IllegalStateException(
                            "required worker schema is missing " + table + "." + column);
                }
            }
        }
    }
}
