package com.elmpay.webhook.ingress;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.sql.DataSource;

/** Bounded, security-definer tenant discovery plus fail-closed startup schema validation. */
public final class JdbcWebhookTenantRegistry {
    private static final Set<String> TABLE_PRIVILEGES = Set.of("SELECT", "INSERT", "UPDATE",
            "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN");
    private static final Set<String> COLUMN_PRIVILEGES = Set.of("SELECT", "INSERT", "UPDATE",
            "REFERENCES");
    private static final Map<String, Set<String>> EXPECTED_PRIVILEGES = Map.ofEntries(
            Map.entry("provider_webhook_inbox", Set.of("SELECT", "UPDATE")),
            Map.entry("provider_webhook_effect_commit", Set.of("SELECT", "INSERT")),
            Map.entry("provider_effect_expectation", Set.of("SELECT")),
            Map.entry("provider_effect_application", Set.of("SELECT", "INSERT")),
            Map.entry("provider_effect_target_clock", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("payment_intent", Set.of("SELECT", "UPDATE")),
            Map.entry("payment_attempt", Set.of("SELECT", "UPDATE")),
            Map.entry("refund", Set.of("SELECT", "UPDATE")),
            Map.entry("provider_account", Set.of("SELECT")),
            Map.entry("outbox_event", Set.of("INSERT")),
            Map.entry("event_aggregate_revision", Set.of("SELECT", "INSERT", "UPDATE")));
    private static final Map<String, List<String>> REQUIRED_SCHEMA;

    static {
        Map<String, List<String>> schema = new LinkedHashMap<>();
        schema.put("provider_webhook_inbox", List.of("inbox_id", "tenant_id", "project_id",
                "provider", "merchant_account_id", "provider_event_id", "event_type",
                "provider_payment_id", "business_order_no", "processing_status",
                "processing_attempts", "next_attempt_at", "lease_owner", "lease_expires_at",
                "fencing_token", "terminal_failure", "canonical_payload_sha256",
                "verification_digest"));
        schema.put("provider_webhook_effect_commit", List.of("tenant_id", "inbox_id",
                "verification_digest", "fencing_token", "committed_at"));
        schema.put("provider_effect_expectation", List.of("tenant_id", "project_id",
                "payment_intent_id", "payment_attempt_id", "provider_account_id", "provider",
                "expected_delta_minor", "currency", "business_order_digest"));
        schema.put("provider_effect_application", List.of("tenant_id", "project_id",
                "provider_account_id", "provider", "provider_event_id", "verification_digest",
                "target_type", "target_id", "outcome"));
        schema.put("provider_effect_target_clock", List.of("tenant_id", "target_type",
                "target_id", "last_provider_occurred_at", "last_provider_event_id"));
        schema.put("payment_intent", List.of("id", "tenant_id", "project_id", "merchant_id",
                "external_reference", "amount_minor", "currency", "captured_amount_minor",
                "refunded_amount_minor", "state", "version"));
        schema.put("payment_attempt", List.of("id", "tenant_id", "payment_intent_id",
                "provider_account_id", "provider", "operation", "sequence", "state",
                "provider_transaction_id"));
        schema.put("refund", List.of("id", "tenant_id", "project_id", "payment_intent_id",
                "provider_account_id", "provider", "provider_payment_id", "provider_refund_id",
                "amount_minor", "currency", "state", "version"));
        schema.put("provider_account", List.of("id", "tenant_id", "project_id", "merchant_id",
                "provider"));
        schema.put("outbox_event", List.of("id", "tenant_id", "project_id",
                "aggregate_type", "aggregate_id", "event_type", "event_version",
                "aggregate_revision", "occurred_at", "recorded_at", "trace_id", "payload"));
        schema.put("event_aggregate_revision", List.of("tenant_id", "aggregate_type",
                "aggregate_id", "current_revision"));
        REQUIRED_SCHEMA = Map.copyOf(schema);
    }

    private static final String ACTIVE_TENANTS_SQL =
            "SELECT tenant_id FROM elmpay_claimable_webhook_tenants(?, ?, ?)";

    private final DataSource dataSource;

    public JdbcWebhookTenantRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public List<String> claimableTenants(int maximum, String afterTenant, Instant dueAt) {
        if (maximum < 1 || maximum > 1000) {
            throw new IllegalArgumentException("maximum tenants must be 1..1000");
        }
        Objects.requireNonNull(dueAt, "dueAt");
        List<String> page = query(maximum, afterTenant, dueAt);
        if (page.isEmpty() && afterTenant != null) {
            return query(maximum, null, dueAt);
        }
        return page;
    }

    private List<String> query(int maximum, String afterTenant, Instant dueAt) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            try (PreparedStatement statement = connection.prepareStatement(ACTIVE_TENANTS_SQL)) {
                statement.setString(1, afterTenant);
                statement.setInt(2, maximum);
                statement.setTimestamp(3, Timestamp.from(dueAt));
                List<String> tenants = new ArrayList<>();
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        String tenant = result.getString("tenant_id");
                        if (tenant == null || !tenant.matches(
                                "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
                            throw new IllegalStateException(
                                    "tenant discovery returned an invalid identifier");
                        }
                        tenants.add(tenant);
                    }
                }
                return List.copyOf(tenants);
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("claimable webhook tenants cannot be loaded", failure);
        }
    }

    public void verifyRequiredSchema() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            setSafeSearchPath(connection);
            requireRestrictedRole(connection);
            requireTenantDiscoveryPrivilege(connection);
            for (Map.Entry<String, List<String>> table : REQUIRED_SCHEMA.entrySet()) {
                requireRealUnownedTable(connection, table.getKey());
                requireRlsTable(connection, table.getKey());
                for (String column : table.getValue()) {
                    requireColumn(connection, table.getKey(), column);
                }
            }
            for (Map.Entry<String, Set<String>> table : EXPECTED_PRIVILEGES.entrySet()) {
                requireExactPrivileges(connection, table.getKey(), table.getValue());
            }
            requireExactSequencePrivileges(connection, "outbox_event_sequence_no_seq",
                    Set.of("USAGE"));
            requireNoUnexpectedRelationSurface(connection);
            requireNoUnexpectedSequenceSurface(connection);
            connection.rollback();
        } catch (SQLException failure) {
            throw new IllegalStateException("webhook processor schema readiness check failed",
                    failure);
        }
    }

    private static void requireRestrictedRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user = 'elmpay_webhook_processor'
                   AND session_user = current_user AND rolcanlogin AND NOT rolinherit
                   AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole
                   AND NOT rolcreatedb AND NOT rolreplication AND rolconfig IS NULL
                   AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid)
                   AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner = r.oid)
                   AND NOT EXISTS (SELECT 1 FROM pg_database
                                    WHERE datname = current_database() AND datdba = r.oid)
                   AND has_schema_privilege(current_user, 'public', 'USAGE')
                   AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
                   AND has_database_privilege(current_user, current_database(), 'CONNECT')
                   AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
                   AND NOT has_database_privilege(current_user, current_database(), 'TEMPORARY')
                   AND current_setting('search_path') = 'pg_catalog,public,pg_temp'
                   AND current_setting('row_security') = 'on'
                   AND NOT EXISTS (
                     SELECT 1 FROM pg_namespace namespace
                      WHERE namespace.nspname NOT IN
                            ('pg_catalog','information_schema','public')
                        AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                        AND (has_schema_privilege(current_user, namespace.oid, 'USAGE')
                          OR has_schema_privilege(current_user, namespace.oid, 'CREATE')))
                  FROM pg_roles
                  AS r
                 WHERE r.rolname = current_user
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.next()) {
                throw new IllegalStateException(
                        "webhook processor database role must not be superuser or bypass RLS");
            }
        }
    }

    private static void requireTenantDiscoveryPrivilege(Connection connection)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*) = 1
                   AND bool_and(p.oid = to_regprocedure(
                         'public.elmpay_claimable_webhook_tenants(text,integer,timestamptz)'))
                   AND bool_and(p.prosecdef AND owner.rolname = 'elmpay_migrator')
                   AND bool_and(COALESCE(p.proconfig, ARRAY[]::text[])
                         @> ARRAY['search_path=pg_catalog, public','row_security=off'])
                   AND bool_and(NOT EXISTS (
                     SELECT 1 FROM aclexplode(COALESCE(
                       p.proacl, acldefault('f', p.proowner))) acl
                      WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'))
                   AND bool_and(position('provider_webhook_inbox' in p.prosrc) > 0
                         AND position('processing_attempts < 100' in p.prosrc) > 0)
                  FROM pg_proc p
                  JOIN pg_namespace n ON n.oid = p.pronamespace
                  JOIN pg_roles owner ON owner.oid = p.proowner
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                   AND has_function_privilege(current_user, p.oid, 'EXECUTE')
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.next()) {
                throw new IllegalStateException(
                        "webhook processor lacks bounded tenant discovery privilege");
            }
        }
    }

    private static void setSafeSearchPath(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('search_path', 'pg_catalog,public,pg_temp', true)")) {
            statement.execute();
        }
    }

    private static void requireRealUnownedTable(Connection connection, String table)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT c.relkind IN ('r','p'), c.relowner = r.oid
                  FROM pg_class c
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE c.oid = to_regclass(?)
                """)) {
            statement.setString(1, "public." + table);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)
                        || result.next()) {
                    throw new IllegalStateException(
                            "webhook processor table is missing, synthetic, or role-owned");
                }
            }
        }
    }

    private static void requireRlsTable(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT relrowsecurity AND relforcerowsecurity
                  FROM pg_class
                 WHERE oid = to_regclass(?)
                """)) {
            statement.setString(1, table);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "required webhook processor table lacks FORCE RLS: " + table);
                }
            }
        }
    }

    private static void requireColumn(Connection connection, String table, String column)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns
                     WHERE table_schema = 'public'
                       AND table_name = ? AND column_name = ?)
                """)) {
            statement.setString(1, table);
            statement.setString(2, column);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "required webhook processor schema is missing " + table + "."
                                    + column);
                }
            }
        }
    }

    private static void requireExactPrivileges(Connection connection, String table,
            Set<String> expected) throws SQLException {
        String qualified = "public." + table;
        for (String privilege : TABLE_PRIVILEGES) {
            boolean actual = tablePrivilege(connection, qualified, privilege);
            if (actual != expected.contains(privilege)) {
                throw new IllegalStateException(
                        "webhook processor table privilege boundary is invalid: " + table);
            }
            if (COLUMN_PRIVILEGES.contains(privilege) && !expected.contains(privilege)
                    && anyColumnPrivilege(connection, qualified, privilege)) {
                throw new IllegalStateException(
                        "webhook processor column privilege bypass is forbidden: " + table);
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT NOT EXISTS (
                  SELECT 1 FROM pg_attribute attribute
                  JOIN pg_class relation ON relation.oid = attribute.attrelid
                  JOIN pg_roles role ON role.rolname = current_user,
                       LATERAL aclexplode(attribute.attacl) acl
                 WHERE relation.oid = to_regclass(?) AND attribute.attnum > 0
                   AND NOT attribute.attisdropped AND acl.grantee IN (0, role.oid))
                  AND NOT EXISTS (
                  SELECT 1 FROM pg_class relation
                  JOIN pg_roles role ON role.rolname = current_user,
                       LATERAL aclexplode(COALESCE(
                         relation.relacl, acldefault('r', relation.relowner))) acl
                 WHERE relation.oid = to_regclass(?)
                   AND acl.grantee IN (0, role.oid) AND acl.is_grantable)
                """)) {
            statement.setString(1, qualified);
            statement.setString(2, qualified);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "webhook processor column or grant-option ACL is forbidden");
                }
            }
        }
    }

    private static boolean tablePrivilege(Connection connection, String table, String privilege)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT has_table_privilege(current_user, ?, ?)")) {
            statement.setString(1, table);
            statement.setString(2, privilege);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        }
    }

    private static boolean anyColumnPrivilege(Connection connection, String table,
            String privilege) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT has_any_column_privilege(current_user, ?, ?)")) {
            statement.setString(1, table);
            statement.setString(2, privilege);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        }
    }

    private static void requireExactSequencePrivileges(Connection connection, String sequence,
            Set<String> expected) throws SQLException {
        String qualified = "public." + sequence;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT c.relkind = 'S', c.relowner = r.oid
                  FROM pg_class c
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE c.oid = to_regclass(?)
                """)) {
            statement.setString(1, qualified);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)
                        || result.next()) {
                    throw new IllegalStateException(
                            "webhook processor sequence is missing, synthetic, or role-owned");
                }
            }
        }
        for (String privilege : Set.of("USAGE", "SELECT", "UPDATE")) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT has_sequence_privilege(current_user, ?, ?)")) {
                statement.setString(1, qualified);
                statement.setString(2, privilege);
                try (ResultSet result = statement.executeQuery()) {
                    boolean actual = result.next() && result.getBoolean(1);
                    if (actual != expected.contains(privilege)) {
                        throw new IllegalStateException(
                                "webhook processor sequence privilege boundary is invalid");
                    }
                }
            }
        }
    }

    private static void requireNoUnexpectedRelationSurface(Connection connection)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT n.nspname, c.relname
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_roles role ON role.rolname = current_user
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                   AND c.relkind IN ('r','p','f','v','m')
                   AND (c.relowner = role.oid
                     OR has_table_privilege(current_user, c.oid, 'SELECT')
                     OR has_table_privilege(current_user, c.oid, 'INSERT')
                     OR has_table_privilege(current_user, c.oid, 'UPDATE')
                     OR has_table_privilege(current_user, c.oid, 'DELETE')
                     OR has_table_privilege(current_user, c.oid, 'TRUNCATE')
                     OR has_table_privilege(current_user, c.oid, 'REFERENCES')
                     OR has_table_privilege(current_user, c.oid, 'TRIGGER')
                     OR has_table_privilege(current_user, c.oid, 'MAINTAIN')
                     OR has_any_column_privilege(current_user, c.oid, 'SELECT')
                     OR has_any_column_privilege(current_user, c.oid, 'INSERT')
                     OR has_any_column_privilege(current_user, c.oid, 'UPDATE')
                     OR has_any_column_privilege(current_user, c.oid, 'REFERENCES'))
                ORDER BY n.nspname, c.relname
                """)) {
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    if (!"public".equals(result.getString(1))
                            || !EXPECTED_PRIVILEGES.containsKey(result.getString(2))) {
                        throw new IllegalStateException(
                                "webhook processor has an unexpected relation or ownership surface");
                    }
                }
            }
        }
    }

    private static void requireNoUnexpectedSequenceSurface(Connection connection)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT n.nspname, c.relname
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_roles role ON role.rolname = current_user
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                   AND c.relkind = 'S'
                   AND (c.relowner = role.oid
                     OR has_sequence_privilege(current_user, c.oid, 'SELECT')
                     OR has_sequence_privilege(current_user, c.oid, 'USAGE')
                     OR has_sequence_privilege(current_user, c.oid, 'UPDATE'))
                ORDER BY n.nspname, c.relname
                """)) {
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    if (!"public".equals(result.getString(1))
                            || !"outbox_event_sequence_no_seq".equals(result.getString(2))) {
                        throw new IllegalStateException(
                                "webhook processor has an unexpected sequence capability");
                    }
                }
            }
        }
    }
}
