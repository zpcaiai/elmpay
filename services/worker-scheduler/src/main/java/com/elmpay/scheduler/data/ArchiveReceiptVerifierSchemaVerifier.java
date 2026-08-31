package com.elmpay.scheduler.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

/** Exact startup ACL proof for the independent receipt-ingestion identity. */
final class ArchiveReceiptVerifierSchemaVerifier {
    static final String ROLE = "elmpay_archive_verifier";
    private final DataSource dataSource;

    ArchiveReceiptVerifierSchemaVerifier(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    void verify() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            requireRole(connection);
            requireFunctions(connection);
            requireNoDirectCapability(connection);
            connection.rollback();
        } catch (SQLException failure) {
            throw new IllegalStateException("archive verifier schema gate failed", failure);
        }
    }

    private static void requireRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user = 'elmpay_archive_verifier', session_user = current_user,
                       rolcanlogin, NOT rolinherit, NOT rolsuper, NOT rolbypassrls,
                       NOT rolcreaterole, NOT rolcreatedb, NOT rolreplication,
                       NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role.oid),
                       NOT has_schema_privilege(current_user, 'public', 'CREATE'),
                       NOT has_database_privilege(current_user, current_database(), 'CREATE'),
                       current_setting('search_path') = 'pg_catalog,public,pg_temp'
                  FROM pg_roles role WHERE role.rolname = current_user
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new IllegalStateException("archive verifier role is absent");
            }
            for (int column = 1; column <= 12; column++) {
                if (!result.getBoolean(column)) {
                    throw new IllegalStateException("archive verifier role is over-privileged");
                }
            }
            if (!result.getBoolean(13) || result.next()) {
                throw new IllegalStateException("archive verifier search path is unsafe");
            }
        }
    }

    private static void requireFunctions(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*) = 3
                   AND bool_and(p.oid IN (
                     to_regprocedure('public.elmpay_record_archive_tenant_receipt(uuid,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz)'),
                     to_regprocedure('public.elmpay_record_archive_partition_release(uuid,text,integer,text,text,text,text,text,text,text,bytea,timestamptz,timestamptz)'),
                     to_regprocedure('public.elmpay_record_archive_detach_authorization(text,uuid,text,text,text,text,text,text,text,text,text,bytea,text,text,bytea,timestamptz,timestamptz)')))
                   AND bool_and(owner.rolname = 'elmpay_migrator')
                   AND bool_and(p.prosecdef AND NOT p.proleakproof)
                   AND bool_and(COALESCE(p.proconfig, ARRAY[]::text[]) =
                     ARRAY['search_path=pg_catalog, public','row_security=on'])
                   AND bool_and(NOT EXISTS (
                     SELECT 1 FROM aclexplode(COALESCE(
                       p.proacl, acldefault('f', p.proowner))) acl
                      WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'))
                   AND bool_and(position('elmpay.archive-maintenance.v1:' in p.prosrc) > 0)
                  FROM pg_proc p
                  JOIN pg_namespace n ON n.oid = p.pronamespace
                  JOIN pg_roles owner ON owner.oid = p.proowner
                 WHERE n.nspname NOT IN ('pg_catalog','information_schema')
                   AND p.prosecdef
                   AND has_function_privilege(current_user, p.oid, 'EXECUTE')
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.next()) {
                throw new IllegalStateException("archive verifier function boundary is invalid");
            }
        }
    }

    private static void requireNoDirectCapability(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*) = 0
                  FROM pg_class relation
                  JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                  JOIN pg_roles role ON role.rolname = current_user
                 WHERE namespace.nspname <> 'information_schema'
                   AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
                   AND ((relation.relkind IN ('r','p','f','v','m')
                     AND (relation.relowner = role.oid
                       OR has_table_privilege(current_user, relation.oid, 'INSERT')
                       OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                       OR has_table_privilege(current_user, relation.oid, 'DELETE')
                       OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                       OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                       OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')
                       OR has_any_column_privilege(current_user, relation.oid, 'INSERT')
                       OR has_any_column_privilege(current_user, relation.oid, 'UPDATE')))
                     OR (relation.relkind = 'S'
                       AND (relation.relowner = role.oid
                         OR has_sequence_privilege(current_user, relation.oid, 'SELECT')
                         OR has_sequence_privilege(current_user, relation.oid, 'USAGE')
                         OR has_sequence_privilege(current_user, relation.oid, 'UPDATE'))))
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next() || !result.getBoolean(1) || result.next()) {
                throw new IllegalStateException("archive verifier has direct data capability");
            }
        }
    }
}
