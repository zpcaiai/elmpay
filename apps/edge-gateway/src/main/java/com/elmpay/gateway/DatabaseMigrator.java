package com.elmpay.gateway;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import javax.sql.DataSource;

/** Checksum-bound, transactional schema migration runner. */
public final class DatabaseMigrator {
    static final String MIGRATION_ROLE = "elmpay_migrator";
    private static final int ADVISORY_NAMESPACE = 1_163_158_352;
    private static final int ADVISORY_KEY = 1;
    private static final List<String> MIGRATIONS = List.of(
            "db/migration/V032__payment_runtime.sql",
            "db/migration/V012__event_delivery_runtime.sql",
            "db/migration/V012_1__event_envelope_revision.sql",
            "db/migration/V013__tenant_partition_archive.sql",
            "db/migration/V023__audit_timestamp_anchor.sql",
            "db/migration/V024__tenant_project_registry.sql",
            "db/migration/V025__merchant_kyb_profile.sql",
            "db/migration/V028__versioned_routing_policy.sql",
            "db/migration/V030__merchant_onboarding_workflow.sql",
            "db/migration/V101__tenant_authority_evidence.sql",
            "V018_019__admin_web_runtime.sql",
            "db/migration/V033__payment_action_receipts.sql",
            "db/migration/V034__durable_refund_runtime.sql",
            "db/migration/V035__payment_intent_metadata.sql",
            "db/migration/V036__payment_attempt_close.sql",
            "db/migration/V036_1__payment_attempt_leases.sql",
            "db/migration/V036_2__verified_provider_effect_runtime.sql",
            "db/migration/V037__provider_webhook_inbox.sql",
            "db/migration/V037_1__provider_webhook_processing.sql",
            "db/migration/V037_2__provider_webhook_processor_runtime.sql",
            "db/migration/V038__business_webhook_delivery.sql",
            "db/migration/V039__payment_timeline_read_model.sql",
            "db/migration/V054__apple_pay_lifecycle.sql",
            "db/migration/V056__checkout_sessions.sql",
            "db/migration/V056_1__checkout_provider_sdk_audit.sql",
            "db/migration/V057__durable_payment_links.sql",
            "db/migration/V062__checkout_capability_health.sql",
            "db/migration/V066__durable_commerce_runtime.sql",
            "db/migration/V066_1__provider_evidence_receipts.sql",
            "db/migration/V072__immutable_ledger.sql",
            "db/migration/V073__event_ledger_posting_policy.sql",
            "db/migration/V076__reconciliation.sql",
            "db/migration/V079__financial_runtime.sql",
            "db/migration/V079_1__reconciliation_snapshot_scheduler.sql",
            "db/migration/V080_087__risk_control.sql",
            "db/migration/V087_1__admin_action_effects.sql",
            "db/migration/V102__risk_engine_runtime.sql",
            "db/migration/V087_2__admin_rollout_effects.sql",
            "db/migration/V103__admin_queue_runtime_role_hardening.sql",
            "db/migration/V104__reconciliation_scheduler_hardening.sql",
            "db/migration/V100__provider_call_circuit.sql",
            "db/migration/V105__provider_tenant_binding_hardening.sql",
            "db/migration/V106__tenant_partition_maintenance_hardening.sql",
            "db/migration/V107__runtime_role_acl_manifest.sql");
    private final DataSource dataSource;

    public DatabaseMigrator(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public void migrate() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setSafeSearchPath(connection);
                requireMigrationRole(connection);
                acquireMigrationLock(connection);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC");
                    statement.execute("""
                            CREATE TABLE IF NOT EXISTS public.elmpay_schema_history (
                                version text PRIMARY KEY,
                                checksum char(64) NOT NULL,
                                installed_at timestamptz NOT NULL
                            )
                            """);
                }
                requireHistoryTable(connection, true);
                for (String resource : MIGRATIONS) {
                    apply(connection, resource);
                }
                try (Statement statement = connection.createStatement()) {
                    statement.execute("REVOKE ALL ON public.elmpay_schema_history FROM PUBLIC");
                    statement.execute("GRANT SELECT ON public.elmpay_schema_history "
                            + "TO elmpay_edge_gateway");
                }
                requireHistoryTable(connection, true);
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("database migration failed", exception);
        }
    }

    /** Read-only runtime gate: production services verify, but never apply, schema changes. */
    public void verifyApplied() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            try {
                setSafeSearchPath(connection);
                requireHistoryTable(connection, false);
                try (PreparedStatement statement = connection.prepareStatement(
                        "SELECT to_regclass('public.elmpay_schema_history') IS NOT NULL");
                        ResultSet result = statement.executeQuery()) {
                    if (!result.next() || !result.getBoolean(1)) {
                        throw new IllegalStateException(
                                "database schema history is missing; run the migration job");
                    }
                }
                for (String resource : MIGRATIONS) {
                    String expected = sha256(read(resource));
                    String actual = checksum(connection, resource, false);
                    if (!expected.equals(actual)) {
                        throw new IllegalStateException(
                                "database migration is missing or checksum-mismatched: "
                                        + resource);
                    }
                }
                connection.rollback();
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("database schema verification failed", failure);
        }
    }

    static List<String> migrationResources() {
        return MIGRATIONS;
    }

    private static void apply(Connection connection, String resource) throws SQLException {
        String script = read(resource);
        String checksum = sha256(script);
        String existing = checksum(connection, resource, true);
        if (existing != null) {
            if (!existing.equals(checksum)) {
                throw new IllegalStateException("migration checksum changed: " + resource);
            }
            return;
        }
        for (String sql : SqlScripts.split(script)) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO public.elmpay_schema_history(version, checksum, installed_at)
                VALUES (?, ?, clock_timestamp())
                """)) {
            statement.setString(1, resource);
            statement.setString(2, checksum);
            statement.executeUpdate();
        }
    }

    private static String checksum(Connection connection, String version, boolean lock)
            throws SQLException {
        String sql = "SELECT checksum FROM public.elmpay_schema_history WHERE version = ?"
                + (lock ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, version);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getString(1) : null;
            }
        }
    }

    private static void setSafeSearchPath(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('search_path', 'pg_catalog,public,pg_temp', true)")) {
            statement.execute();
        }
    }

    private static void acquireMigrationLock(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?, ?)")) {
            statement.setInt(1, ADVISORY_NAMESPACE);
            statement.setInt(2, ADVISORY_KEY);
            statement.execute();
        }
    }

    private static void requireMigrationRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user, session_user, rolcanlogin, rolsuper, rolbypassrls,
                       rolcreaterole, rolcreatedb, rolreplication,
                       EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid),
                       (SELECT nspowner = r.oid FROM pg_namespace WHERE nspname = 'public'),
                       (SELECT datdba = r.oid FROM pg_database WHERE datname = current_database()),
                       current_setting('search_path')
                  FROM pg_roles r
                 WHERE r.rolname = current_user
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !MIGRATION_ROLE.equals(result.getString(1))
                    || !MIGRATION_ROLE.equals(result.getString(2)) || !result.getBoolean(3)
                    || result.getBoolean(4) || result.getBoolean(5) || result.getBoolean(6)
                    || result.getBoolean(7) || result.getBoolean(8) || result.getBoolean(9)
                    || !result.getBoolean(10) || !result.getBoolean(11)
                    || !"pg_catalog,public,pg_temp".equals(result.getString(12))) {
                throw new IllegalStateException(
                        "database migration requires the dedicated non-superuser owner role");
            }
        }
    }

    private static void requireHistoryTable(Connection connection, boolean migrationSession)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT c.relkind = 'r', owner.rolname = ?, c.relrowsecurity,
                       count(column_name) = 3,
                       bool_and((ordinal_position = 1 AND column_name = 'version'
                                   AND data_type = 'text' AND is_nullable = 'NO')
                             OR (ordinal_position = 2 AND column_name = 'checksum'
                                   AND data_type = 'character' AND character_maximum_length = 64
                                   AND is_nullable = 'NO')
                             OR (ordinal_position = 3 AND column_name = 'installed_at'
                                   AND data_type = 'timestamp with time zone'
                                   AND is_nullable = 'NO')),
                       EXISTS (
                         SELECT 1 FROM pg_constraint constraint
                          WHERE constraint.conrelid = c.oid AND constraint.contype = 'p'
                            AND constraint.conkey = ARRAY[
                              (SELECT attnum FROM pg_attribute
                                WHERE attrelid = c.oid AND attname = 'version')]
                       ),
                       NOT has_table_privilege('PUBLIC', c.oid, 'SELECT')
                         AND NOT has_table_privilege('PUBLIC', c.oid, 'INSERT')
                         AND NOT has_table_privilege('PUBLIC', c.oid, 'UPDATE')
                         AND NOT has_table_privilege('PUBLIC', c.oid, 'DELETE'),
                       has_table_privilege('elmpay_edge_gateway', c.oid, 'SELECT')
                         OR ?
                  FROM pg_class c
                  JOIN pg_namespace namespace ON namespace.oid = c.relnamespace
                  JOIN pg_roles owner ON owner.oid = c.relowner
                  JOIN information_schema.columns columns
                    ON columns.table_schema = namespace.nspname
                   AND columns.table_name = c.relname
                 WHERE namespace.nspname = 'public'
                   AND c.relname = 'elmpay_schema_history'
                 GROUP BY c.oid, c.relkind, owner.rolname, c.relrowsecurity
                """)) {
            statement.setString(1, MIGRATION_ROLE);
            statement.setBoolean(2, migrationSession);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || !result.getBoolean(2)
                        || result.getBoolean(3) || !result.getBoolean(4)
                        || !result.getBoolean(5) || !result.getBoolean(6)
                        || !result.getBoolean(7) || !result.getBoolean(8)) {
                    throw new IllegalStateException(
                            "database schema history table is synthetic or over-privileged");
                }
            }
        }
    }

    private static String read(String resource) {
        ClassLoader loader = DatabaseMigrator.class.getClassLoader();
        try (InputStream input = loader.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("migration resource is missing: " + resource);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalStateException("cannot read migration: " + resource, exception);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK is missing SHA-256", exception);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
