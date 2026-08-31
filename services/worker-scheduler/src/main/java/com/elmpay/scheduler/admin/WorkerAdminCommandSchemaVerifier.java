package com.elmpay.scheduler.admin;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.sql.DataSource;

/** Startup least-privilege and FORCE-RLS gate for every worker-scheduler JDBC path. */
public final class WorkerAdminCommandSchemaVerifier {
    private static final Set<String> TABLE_PRIVILEGES = Set.of("SELECT", "INSERT", "UPDATE",
            "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN");
    private static final Set<String> COLUMN_PRIVILEGES = Set.of("SELECT", "INSERT", "UPDATE",
            "REFERENCES");
    private static final Map<String, Set<String>> EXPECTED = Map.ofEntries(
            // Shared admin queue and foreign owner tables are reachable only through narrow
            // SECURITY DEFINER APIs.  Keeping them in this inventory proves zero direct ACL.
            Map.entry("admin_domain_command", Set.of()),
            Map.entry("admin_domain_command_signal", Set.of()),
            Map.entry("admin_action_effect_receipt", Set.of()),
            Map.entry("rollout_execution", Set.of()),
            Map.entry("admin_rollout_stage_approval", Set.of()),
            Map.entry("refund", Set.of("SELECT")),
            Map.entry("refund_action_receipt", Set.of()),
            Map.entry("risk_runtime_operation_request", Set.of()),
            Map.entry("risk_runtime_list_entry", Set.of()),
            Map.entry("risk_runtime_case_resolution", Set.of()),

            // Durable event relay and financial ledger consumer.
            Map.entry("event_aggregate_revision", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("outbox_event", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("consumer_event_inbox", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("ledger_event_revision_guard", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("ledger_account", Set.of("SELECT")),
            Map.entry("ledger_transaction", Set.of("SELECT", "INSERT")),
            Map.entry("ledger_entry", Set.of("SELECT", "INSERT")),
            Map.entry("ledger_posting_policy", Set.of("SELECT")),
            Map.entry("ledger_posting_account_mapping", Set.of("SELECT")),

            // The production scheduler invokes only enqueueDueRenewal/enqueueDueDunning; it
            // cannot call the broader commerce administrative surface.
            Map.entry("billing_plan", Set.of("SELECT")),
            Map.entry("billing_subscription", Set.of("SELECT", "UPDATE")),
            Map.entry("subscription_billing_cycle", Set.of("SELECT", "INSERT")),
            Map.entry("dunning_case", Set.of("SELECT", "UPDATE")),

            // Reconciliation scheduler/fact snapshot and payment timeline projection.
            Map.entry("payment_intent", Set.of("SELECT")),
            Map.entry("provider_account", Set.of("SELECT")),
            Map.entry("provider_capability", Set.of("SELECT")),
            Map.entry("statement_file", Set.of("SELECT")),
            Map.entry("statement_row", Set.of("SELECT")),
            Map.entry("financial_runtime_job", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("recon_run", Set.of("SELECT", "INSERT")),
            Map.entry("recon_match", Set.of("SELECT", "INSERT")),
            Map.entry("recon_exception_current", Set.of("INSERT")),
            Map.entry("recon_exception_action", Set.of("INSERT")),
            Map.entry("recon_exception_origin", Set.of("INSERT")),
            Map.entry("reconciliation_fact_snapshot", Set.of("SELECT", "INSERT")),
            Map.entry("reconciliation_fact_snapshot_member", Set.of("SELECT", "INSERT")),
            Map.entry("reconciliation_schedule_cursor", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("payment_projection_checkpoint", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("payment_status_read_model",
                    Set.of("SELECT", "INSERT", "UPDATE", "DELETE")),
            Map.entry("payment_timeline_event", Set.of("SELECT", "INSERT", "DELETE")),

            // External audit anchoring and webhook delivery are mounted, fail-closed worker
            // components.  They have no endpoint administration/replay capability.
            Map.entry("audit_event", Set.of("SELECT")),
            Map.entry("audit_anchor_request", Set.of("SELECT", "INSERT", "UPDATE")),
            Map.entry("audit_anchor_receipt", Set.of("INSERT")),
            Map.entry("webhook_endpoint", Set.of("SELECT")),
            Map.entry("webhook_signing_key", Set.of("SELECT")),
            Map.entry("webhook_delivery_outbox", Set.of("SELECT", "UPDATE")),
            Map.entry("webhook_delivery_dead_letter", Set.of("INSERT")));
    private static final List<String> FORCE_RLS = List.copyOf(EXPECTED.keySet());

    private final DataSource dataSource;

    public WorkerAdminCommandSchemaVerifier(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public void verify() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            setSafeSearchPath(connection);
            requireLeastPrivilegeSession(connection);
            for (String table : EXPECTED.keySet()) {
                requireRealUnownedTable(connection, table);
            }
            for (String table : FORCE_RLS) {
                requireForcedRls(connection, table);
            }
            for (Map.Entry<String, Set<String>> table : EXPECTED.entrySet()) {
                requireExactPrivileges(connection, table.getKey(), table.getValue());
            }
            requireExactSequencePrivileges(connection, "outbox_event_sequence_no_seq",
                    Set.of("USAGE"));
            requireNoUnexpectedRelationSurface(connection);
            requireNoUnexpectedSequenceSurface(connection);
            requireNoWritableView(connection);
            requireExactSecurityDefinerCapability(connection);
            connection.rollback();
        } catch (SQLException failure) {
            throw new IllegalStateException("worker admin schema validation failed", failure);
        }
    }

    private static void requireLeastPrivilegeSession(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user = 'elmpay_worker'
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
                 FROM pg_roles r
                 WHERE r.rolname = current_user
                """)) {
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "worker admin consumer database identity is not least privilege");
                }
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
                if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)) {
                    throw new IllegalStateException(
                            "worker admin table is missing, synthetic, or role-owned");
                }
            }
        }
    }

    private static void requireForcedRls(Connection connection, String table)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT relrowsecurity AND relforcerowsecurity
                  FROM pg_class
                 WHERE oid = to_regclass(?)
                """)) {
            statement.setString(1, "public." + table);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1)) {
                    throw new IllegalStateException("worker admin table must FORCE RLS");
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
                        "worker admin table privilege boundary is invalid");
            }
            if (COLUMN_PRIVILEGES.contains(privilege) && !expected.contains(privilege)
                    && anyColumnPrivilege(connection, qualified, privilege)) {
                throw new IllegalStateException(
                        "worker admin column privilege bypass is forbidden");
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
                            "worker runtime column or grant-option ACL is forbidden");
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
                if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)) {
                    throw new IllegalStateException(
                            "worker admin sequence is missing, synthetic, or role-owned");
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
                                "worker admin sequence privilege boundary is invalid");
                    }
                }
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT NOT EXISTS (
                  SELECT 1 FROM pg_class sequence
                  JOIN pg_roles role ON role.rolname = current_user,
                       LATERAL aclexplode(COALESCE(
                         sequence.relacl, acldefault('S', sequence.relowner))) acl
                 WHERE sequence.oid = to_regclass(?)
                   AND acl.grantee IN (0, role.oid) AND acl.is_grantable)
                """)) {
            statement.setString(1, qualified);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "worker runtime sequence grant option is forbidden");
                }
            }
        }
    }

    private static void requireExactSecurityDefinerCapability(Connection connection)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*) = 7
                       AND bool_and(p.oid = ANY (ARRAY[
                         to_regprocedure('public.elmpay_active_worker_scopes(uuid,uuid,integer)'),
                         to_regprocedure('public.elmpay_admin_claim_command(text,bigint)'),
                         to_regprocedure('public.elmpay_admin_complete_command(uuid,uuid,text,bigint,uuid,text)'),
                         to_regprocedure('public.elmpay_admin_retry_command(uuid,uuid,text,bigint,text,text,timestamptz,boolean)'),
                         to_regprocedure('public.elmpay_admin_block_command(uuid,uuid,text,bigint,text,text)'),
                         to_regprocedure('public.elmpay_admin_find_effect_receipt(uuid,text)'),
                         to_regprocedure('public.elmpay_apply_admin_rollout_approval(uuid,uuid,text,bigint,uuid)')
                       ]))
                       AND bool_and(p.prosecdef)
                       AND bool_and(owner.rolname = 'elmpay_migrator')
                       AND bool_and(COALESCE(p.proconfig, ARRAY[]::text[])
                         @> ARRAY['search_path=pg_catalog, public'])
                       AND bool_and((p.proname = 'elmpay_active_worker_scopes'
                           AND COALESCE(p.proconfig, ARRAY[]::text[]) @> ARRAY['row_security=off'])
                         OR (p.proname <> 'elmpay_active_worker_scopes'
                           AND COALESCE(p.proconfig, ARRAY[]::text[]) @> ARRAY['row_security=on']))
                       AND bool_and(NOT EXISTS (
                         SELECT 1 FROM aclexplode(COALESCE(
                           p.proacl, acldefault('f', p.proowner))) acl
                          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'))
                       AND bool_and(p.proname IN ('elmpay_active_worker_scopes')
                         OR position('elmpay.admin-command-db-api.v1' in p.prosrc) > 0)
                  FROM pg_proc p
                  JOIN pg_namespace n ON n.oid = p.pronamespace
                  JOIN pg_roles owner ON owner.oid = p.proowner
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                   AND has_function_privilege(current_user, p.oid, 'EXECUTE')
                """)) {
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1)) {
                    throw new IllegalStateException(
                            "worker SECURITY DEFINER capability boundary is invalid");
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
                            || !EXPECTED.containsKey(result.getString(2))) {
                        throw new IllegalStateException(
                                "worker runtime has an unexpected relation or ownership surface");
                    }
                }
            }
        }
    }

    /** Views are read-only policy surfaces; writable view ACLs would bypass the table inventory. */
    private static void requireNoWritableView(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT NOT EXISTS (
                  SELECT 1
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_roles role ON role.rolname = current_user
                   WHERE n.nspname = 'public' AND c.relkind IN ('v','m')
                     AND (c.relowner = role.oid
                       OR has_table_privilege(current_user, c.oid, 'INSERT')
                       OR has_table_privilege(current_user, c.oid, 'UPDATE')
                       OR has_table_privilege(current_user, c.oid, 'DELETE'))
                )
                """)) {
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.next()) {
                    throw new IllegalStateException(
                            "worker runtime exposes a writable view capability");
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
                                "worker runtime has an unexpected sequence capability");
                    }
                }
            }
        }
    }
}
