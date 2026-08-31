package com.elmpay.risk.runtime;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;

/** Startup gate for the dedicated, non-owning risk runtime PostgreSQL identity. */
final class RiskRuntimeSchemaVerifier {
    private static final Set<String> REQUIRED_SEARCH_PATH_RENDERINGS = Set.of(
            "pg_catalog,public,pg_temp", "pg_catalog, public, pg_temp");
    private static final List<String> TABLE_PRIVILEGES = List.of("SELECT", "INSERT", "UPDATE",
            "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN");
    private static final Set<String> COLUMN_PRIVILEGES = Set.of("SELECT", "INSERT", "UPDATE",
            "REFERENCES");
    private static final List<String> SEQUENCE_PRIVILEGES = List.of("SELECT", "USAGE", "UPDATE");
    private static final Set<String> EXACT_TENANT_POLICY_TABLES = Set.of(
            "risk_runtime_nonce", "risk_runtime_rule_set", "risk_runtime_signal_snapshot",
            "risk_runtime_model_result", "risk_runtime_decision",
            "risk_runtime_operation_request", "risk_runtime_list_entry",
            "risk_runtime_case_resolution", "risk_runtime_audit",
            "event_aggregate_revision", "outbox_event");
    private static final Set<String> EXACT_TENANT_POLICY_EXPRESSIONS = Set.of(
            "tenant_id=(current_setting('app.tenant_id'::text))::uuid",
            "tenant_id=(current_setting('app.tenant_id'::text,true))::uuid",
            "tenant_id=(NULLIF(current_setting('app.tenant_id'::text,true),''::text))::uuid");

    private static final List<TableBoundary> REQUIRED_TABLES = List.of(
            table("risk_runtime_nonce", true, "SELECT", "INSERT", "UPDATE"),
            table("risk_runtime_rule_set", true, "SELECT", "INSERT", "UPDATE"),
            table("risk_runtime_capability_health", false, "SELECT", "INSERT", "UPDATE"),
            table("risk_runtime_signal_snapshot", true, "INSERT"),
            table("risk_runtime_model_result", true, "INSERT"),
            table("risk_runtime_decision", true, "SELECT", "INSERT"),
            table("risk_runtime_operation_request", true, "SELECT", "INSERT", "UPDATE"),
            table("risk_runtime_list_entry", true, "INSERT", "UPDATE"),
            table("risk_runtime_case_resolution", true, "INSERT"),
            table("risk_runtime_audit", true, "INSERT"),
            table("event_aggregate_revision", true, "SELECT", "INSERT", "UPDATE"),
            table("outbox_event", true, "INSERT"),
            table("admin_domain_command", true),
            table("admin_domain_command_signal", true),
            table("admin_action_effect_receipt", true));

    private static final List<SequenceBoundary> REQUIRED_SEQUENCES = List.of(
            sequence("risk_runtime_audit_sequence_no_seq", "USAGE"),
            sequence("outbox_event_sequence_no_seq", "USAGE"));

    private final DataSource dataSource;
    private final AtomicBoolean verified = new AtomicBoolean();

    RiskRuntimeSchemaVerifier(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    void verify() {
        verified.set(false);
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            requireRuntimeRole(connection);
            requireSchemaBoundary(connection);
            requireDatabaseBoundary(connection);
            requireExactSecurityDefinerCapability(connection);
            for (TableBoundary boundary : REQUIRED_TABLES) {
                requireTableBoundary(connection, boundary);
            }
            requireNoCrossDomainRelationPrivilege(connection);
            for (SequenceBoundary boundary : REQUIRED_SEQUENCES) {
                requireSequenceBoundary(connection, boundary);
            }
            requireNoCrossDomainSequencePrivilege(connection);
            connection.rollback();
            verified.set(true);
        } catch (SQLException failure) {
            throw new IllegalStateException("risk runtime schema validation failed", failure);
        }
    }

    boolean ready() {
        return verified.get();
    }

    private static void requireRuntimeRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user, session_user, rolcanlogin, rolinherit,
                       rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication,
                       current_setting('search_path'),
                       NOT EXISTS (SELECT 1 FROM pg_auth_members membership
                                    WHERE membership.member = runtime_role.oid),
                       COALESCE(array_length(runtime_role.rolconfig, 1), 0) = 0,
                       current_setting('row_security') = 'on'
                  FROM pg_roles runtime_role
                 WHERE runtime_role.rolname = current_user
                """)) {
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()
                        || !RiskPostgresDataSource.RUNTIME_DATABASE_ROLE.equals(result.getString(1))
                        || !RiskPostgresDataSource.RUNTIME_DATABASE_ROLE.equals(result.getString(2))
                        || !result.getBoolean(3) || result.getBoolean(4)
                        || result.getBoolean(5) || result.getBoolean(6)
                        || result.getBoolean(7) || result.getBoolean(8)
                        || result.getBoolean(9)
                        || !REQUIRED_SEARCH_PATH_RENDERINGS.contains(result.getString(10))
                        || !result.getBoolean(11) || !result.getBoolean(12)
                        || !result.getBoolean(13) || result.next()) {
                    throw new IllegalStateException(
                            "risk runtime must use its exact non-privileged login role");
                }
            }
        }
    }

    private static void requireSchemaBoundary(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT has_schema_privilege(current_user, 'public', 'USAGE'),
                       has_schema_privilege(current_user, 'public', 'CREATE'),
                       n.nspowner = r.oid
                  FROM pg_namespace n
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE n.nspname = 'public'
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)
                    || result.getBoolean(3) || result.next()) {
                throw new IllegalStateException("risk runtime public schema boundary is invalid");
            }
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT n.nspname
                  FROM pg_namespace n
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE n.nspname <> 'public'
                   AND n.nspname <> 'information_schema'
                   AND n.nspname !~ '^pg_'
                   AND (n.nspowner = r.oid
                     OR has_schema_privilege(current_user, n.oid, 'USAGE')
                     OR has_schema_privilege(current_user, n.oid, 'CREATE'))
                 ORDER BY n.nspname
                """); ResultSet result = statement.executeQuery()) {
            if (result.next()) {
                throw new IllegalStateException(
                        "risk runtime has access to a forbidden application schema");
            }
        }
    }

    private static void requireDatabaseBoundary(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT has_database_privilege(current_user, current_database(), 'CONNECT'),
                       has_database_privilege(current_user, current_database(), 'CREATE'),
                       has_database_privilege(current_user, current_database(), 'TEMP'),
                       d.datdba = r.oid
                  FROM pg_database d
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE d.datname = current_database()
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)
                    || result.getBoolean(3) || result.getBoolean(4) || result.next()) {
                throw new IllegalStateException("risk runtime database boundary is invalid");
            }
        }
    }

    private static void requireExactSecurityDefinerCapability(Connection connection)
            throws SQLException {
        // Queue table ACLs stay empty. These five narrowly scoped routines derive the consumer
        // group from session_user, use the database clock/fence, and own the only queue mutation
        // surface available to this role.
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*) = 5
                       AND bool_and(p.oid = ANY (ARRAY[
                         to_regprocedure('public.elmpay_admin_claim_command(text,bigint)'),
                         to_regprocedure('public.elmpay_admin_complete_command(uuid,uuid,text,bigint,uuid,text)'),
                         to_regprocedure('public.elmpay_admin_retry_command(uuid,uuid,text,bigint,text,text,timestamptz,boolean)'),
                         to_regprocedure('public.elmpay_admin_block_command(uuid,uuid,text,bigint,text,text)'),
                         to_regprocedure('public.elmpay_admin_find_effect_receipt(uuid,text)')
                       ]))
                       AND bool_and(owner.rolname = 'elmpay_migrator')
                       AND bool_and(p.prosecdef AND p.prokind = 'f' AND NOT p.proleakproof)
                       AND bool_and(COALESCE(p.proconfig, ARRAY[]::text[])
                         @> ARRAY['search_path=pg_catalog, public', 'row_security=on'])
                       AND bool_and(COALESCE(p.proconfig, ARRAY[]::text[])
                         <@ ARRAY['search_path=pg_catalog, public', 'row_security=on'])
                       AND bool_and(NOT EXISTS (
                         SELECT 1
                           FROM aclexplode(COALESCE(
                             p.proacl, acldefault('f', p.proowner))) public_acl
                          WHERE public_acl.grantee = 0
                            AND public_acl.privilege_type = 'EXECUTE'))
                       AND bool_and(has_function_privilege(
                         'elmpay_edge_gateway', p.oid, 'EXECUTE'))
                       AND bool_and(has_function_privilege(
                         'elmpay_risk_engine', p.oid, 'EXECUTE'))
                       AND bool_and(has_function_privilege(
                         'elmpay_worker', p.oid, 'EXECUTE'))
                       AND bool_and(position(
                         'elmpay.admin-command-db-api.v1' in p.prosrc) > 0)
                       AND bool_and(CASE p.proname
                         WHEN 'elmpay_admin_claim_command' THEN
                           position('elmpay.admin-command-db-api.v1:group-claim'
                             in p.prosrc) > 0
                         WHEN 'elmpay_admin_complete_command' THEN
                           position('elmpay.admin-command-db-api.v1:effect-commit'
                             in p.prosrc) > 0
                         WHEN 'elmpay_admin_retry_command' THEN
                           position('elmpay.admin-command-db-api.v1:retry-or-unknown'
                             in p.prosrc) > 0
                         WHEN 'elmpay_admin_block_command' THEN
                           position('elmpay.admin-command-db-api.v1:block'
                             in p.prosrc) > 0
                         WHEN 'elmpay_admin_find_effect_receipt' THEN
                           position('elmpay.admin-command-db-api.v1:owned-receipt-reconcile'
                             in p.prosrc) > 0
                         ELSE false END)
                       AND bool_and(NOT EXISTS (
                         SELECT 1
                           FROM aclexplode(COALESCE(
                             p.proacl, acldefault('f', p.proowner))) acl
                          WHERE acl.privilege_type = 'EXECUTE'
                            AND (acl.grantee = 0 OR acl.is_grantable
                              OR acl.grantee NOT IN (
                                p.proowner,
                                (SELECT oid FROM pg_roles
                                  WHERE rolname = 'elmpay_edge_gateway'),
                                (SELECT oid FROM pg_roles
                                  WHERE rolname = 'elmpay_risk_engine'),
                                (SELECT oid FROM pg_roles
                                  WHERE rolname = 'elmpay_worker')))))
                  FROM pg_proc p
                  JOIN pg_namespace n ON n.oid = p.pronamespace
                  JOIN pg_roles owner ON owner.oid = p.proowner
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname !~ '^pg_'
                   AND has_function_privilege(current_user, p.oid, 'EXECUTE')
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.next()) {
                throw new IllegalStateException(
                        "risk runtime SECURITY DEFINER capability boundary is invalid");
            }
        }
    }

    private static void requireTableBoundary(Connection connection, TableBoundary boundary)
            throws SQLException {
        String relation = qualified(boundary.name());
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT c.relkind IN ('r', 'p'), c.relowner = r.oid,
                       c.relrowsecurity, c.relforcerowsecurity
                  FROM pg_class c
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE c.oid = to_regclass(?)
                """)) {
            statement.setString(1, relation);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)
                        || (boundary.forceRls()
                                && (!result.getBoolean(3) || !result.getBoolean(4)))
                        || result.next()) {
                    throw new IllegalStateException("risk runtime table boundary is invalid");
                }
            }
        }
        for (String privilege : TABLE_PRIVILEGES) {
            requireTablePrivilege(connection, relation, privilege,
                    boundary.allowedPrivileges().contains(privilege));
        }
        if (EXACT_TENANT_POLICY_TABLES.contains(boundary.name())) {
            requireExactTenantPolicy(connection, boundary.name());
        }
    }

    private static void requireExactTenantPolicy(Connection connection, String table)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT p.polname,
                       p.polpermissive,
                       p.polroles = ARRAY[0]::oid[],
                       p.polcmd = '*',
                       pg_get_expr(p.polqual, p.polrelid),
                       pg_get_expr(p.polwithcheck, p.polrelid)
                  FROM pg_policy p
                 WHERE p.polrelid = to_regclass(?)
                """)) {
            statement.setString(1, qualified(table));
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()
                        || !(table + "_tenant_policy").equals(result.getString(1))
                        || !result.getBoolean(2) || !result.getBoolean(3)
                        || !result.getBoolean(4)
                        || !exactTenantExpression(result.getString(5))
                        || !Objects.equals(result.getString(5), result.getString(6))
                        || result.next()) {
                    throw new IllegalStateException(
                            "risk runtime tenant policy boundary is invalid");
                }
            }
        }
    }

    static boolean exactTenantExpression(String expression) {
        if (expression == null) {
            return false;
        }
        String normalized = removeUnquotedWhitespace(expression);
        while (normalized.length() > 1 && normalized.charAt(0) == '('
                && normalized.charAt(normalized.length() - 1) == ')'
                && enclosesWholeExpression(normalized)) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return EXACT_TENANT_POLICY_EXPRESSIONS.contains(normalized);
    }

    private static boolean enclosesWholeExpression(String expression) {
        int depth = 0;
        boolean quoted = false;
        for (int index = 0; index < expression.length(); index++) {
            char value = expression.charAt(index);
            if (value == '\'') {
                if (quoted && index + 1 < expression.length()
                        && expression.charAt(index + 1) == '\'') {
                    index++;
                } else {
                    quoted = !quoted;
                }
            } else if (!quoted && value == '(') {
                depth++;
            } else if (!quoted && value == ')' && --depth == 0) {
                return index == expression.length() - 1;
            }
        }
        return false;
    }

    private static String removeUnquotedWhitespace(String expression) {
        StringBuilder normalized = new StringBuilder(expression.length());
        boolean quoted = false;
        for (int index = 0; index < expression.length(); index++) {
            char value = expression.charAt(index);
            if (value == '\'') {
                normalized.append(value);
                if (quoted && index + 1 < expression.length()
                        && expression.charAt(index + 1) == '\'') {
                    normalized.append(expression.charAt(++index));
                } else {
                    quoted = !quoted;
                }
            } else if (quoted || !Character.isWhitespace(value)) {
                normalized.append(value);
            }
        }
        return quoted ? "" : normalized.toString();
    }

    private static void requireNoCrossDomainRelationPrivilege(Connection connection)
            throws SQLException {
        // Deliberately discover relations instead of keeping a payment/refund/rollout denylist.
        // A later migration must not silently give this workload read or write access to a new
        // table, partition, foreign table, view, or materialized view.
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT n.nspname, c.relname
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname !~ '^pg_'
                   AND c.relkind IN ('r', 'p', 'f', 'v', 'm')
                   AND (has_table_privilege(current_user, c.oid, 'SELECT')
                     OR has_any_column_privilege(current_user, c.oid, 'SELECT')
                     OR has_table_privilege(current_user, c.oid, 'INSERT')
                     OR has_any_column_privilege(current_user, c.oid, 'INSERT')
                     OR has_table_privilege(current_user, c.oid, 'UPDATE')
                     OR has_any_column_privilege(current_user, c.oid, 'UPDATE')
                     OR has_table_privilege(current_user, c.oid, 'DELETE')
                     OR has_table_privilege(current_user, c.oid, 'TRUNCATE')
                     OR has_table_privilege(current_user, c.oid, 'REFERENCES')
                     OR has_any_column_privilege(current_user, c.oid, 'REFERENCES')
                     OR has_table_privilege(current_user, c.oid, 'TRIGGER')
                     OR has_table_privilege(current_user, c.oid, 'MAINTAIN'))
                 ORDER BY n.nspname, c.relname
                """); ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                String schema = result.getString(1);
                String relation = result.getString(2);
                if (!"public".equals(schema) || REQUIRED_TABLES.stream()
                        .noneMatch(table -> table.name().equals(relation))) {
                    throw new IllegalStateException(
                            "risk runtime has a forbidden cross-domain relation privilege");
                }
            }
        }
    }

    private static void requireTablePrivilege(Connection connection, String relation,
            String privilege, boolean expected) throws SQLException {
        String sql = COLUMN_PRIVILEGES.contains(privilege)
                ? """
                  SELECT COALESCE(has_table_privilege(current_user, to_regclass(?), ?), false),
                         COALESCE(has_any_column_privilege(current_user, to_regclass(?), ?), false)
                  """
                : """
                  SELECT COALESCE(has_table_privilege(current_user, to_regclass(?), ?), false),
                         false
                  """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, relation);
            statement.setString(2, privilege);
            if (COLUMN_PRIVILEGES.contains(privilege)) {
                statement.setString(3, relation);
                statement.setString(4, privilege);
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("risk runtime privilege result is unavailable");
                }
                boolean tablePrivilege = result.getBoolean(1);
                boolean anyColumnPrivilege = result.getBoolean(2);
                if ((expected && !tablePrivilege)
                        || (!expected && (tablePrivilege || anyColumnPrivilege)) || result.next()) {
                    throw new IllegalStateException("risk runtime table privilege boundary is invalid");
                }
            }
        }
    }

    private static void requireSequenceBoundary(Connection connection, SequenceBoundary boundary)
            throws SQLException {
        String relation = qualified(boundary.name());
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT c.relkind = 'S', c.relowner = r.oid
                  FROM pg_class c
                  JOIN pg_roles r ON r.rolname = current_user
                 WHERE c.oid = to_regclass(?)
                """)) {
            statement.setString(1, relation);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next() || !result.getBoolean(1) || result.getBoolean(2)
                        || result.next()) {
                    throw new IllegalStateException("risk runtime sequence boundary is invalid");
                }
            }
        }
        for (String privilege : SEQUENCE_PRIVILEGES) {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT COALESCE(has_sequence_privilege(
                        current_user, to_regclass(?), ?), false)
                    """)) {
                statement.setString(1, relation);
                statement.setString(2, privilege);
                try (ResultSet result = statement.executeQuery()) {
                    boolean actual = result.next() && result.getBoolean(1);
                    if (actual != boundary.allowedPrivileges().contains(privilege)
                            || result.next()) {
                        throw new IllegalStateException(
                                "risk runtime sequence privilege boundary is invalid");
                    }
                }
            }
        }
    }

    private static void requireNoCrossDomainSequencePrivilege(Connection connection)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT n.nspname, c.relname
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname <> 'information_schema'
                   AND n.nspname !~ '^pg_'
                   AND c.relkind = 'S'
                   AND (has_sequence_privilege(current_user, c.oid, 'SELECT')
                     OR has_sequence_privilege(current_user, c.oid, 'USAGE')
                     OR has_sequence_privilege(current_user, c.oid, 'UPDATE'))
                 ORDER BY n.nspname, c.relname
                """); ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                String schema = result.getString(1);
                String relation = result.getString(2);
                if (!"public".equals(schema) || REQUIRED_SEQUENCES.stream()
                        .noneMatch(sequence -> sequence.name().equals(relation))) {
                    throw new IllegalStateException(
                            "risk runtime has a forbidden cross-domain sequence privilege");
                }
            }
        }
    }

    private static String qualified(String relation) {
        if (relation == null || !relation.matches("[a-z][a-z0-9_]{0,62}")) {
            throw new IllegalArgumentException("risk runtime relation name is invalid");
        }
        return "public." + relation;
    }

    private static TableBoundary table(String name, boolean forceRls, String... privileges) {
        return new TableBoundary(name, forceRls, Set.of(privileges));
    }

    private static SequenceBoundary sequence(String name, String... privileges) {
        return new SequenceBoundary(name, Set.of(privileges));
    }

    private record TableBoundary(String name, boolean forceRls,
            Set<String> allowedPrivileges) { }

    private record SequenceBoundary(String name, Set<String> allowedPrivileges) { }
}
