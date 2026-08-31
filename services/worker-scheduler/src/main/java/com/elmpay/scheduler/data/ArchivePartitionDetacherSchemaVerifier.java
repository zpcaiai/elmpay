package com.elmpay.scheduler.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

/** Proves that the detach login has only two narrow, audited capabilities. */
final class ArchivePartitionDetacherSchemaVerifier {
    private final DataSource dataSource;

    ArchivePartitionDetacherSchemaVerifier(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    void verify() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            requireExactRole(connection);
            requireExactFunctions(connection);
            requireNoDirectDataCapability(connection);
            connection.rollback();
        } catch (SQLException failure) {
            throw new IllegalStateException("archive detacher schema gate failed", failure);
        }
    }

    private static void requireExactRole(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_user, session_user, rolcanlogin, rolsuper, rolbypassrls,
                       rolcreaterole, rolcreatedb, rolreplication, rolinherit,
                       EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role.oid),
                       has_schema_privilege(current_user, 'public', 'CREATE'),
                       has_database_privilege(current_user, current_database(), 'CREATE'),
                       (SELECT nspowner = role.oid FROM pg_namespace WHERE nspname = 'public'),
                       (SELECT datdba = role.oid FROM pg_database
                         WHERE datname = current_database()),
                       current_setting('search_path')
                  FROM pg_roles role WHERE role.rolname = current_user
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next()
                    || !ArchivePartitionDetacherSettings.DATABASE_ROLE.equals(result.getString(1))
                    || !ArchivePartitionDetacherSettings.DATABASE_ROLE.equals(result.getString(2))
                    || !result.getBoolean(3) || result.getBoolean(4) || result.getBoolean(5)
                    || result.getBoolean(6) || result.getBoolean(7) || result.getBoolean(8)
                    || result.getBoolean(9) || result.getBoolean(10) || result.getBoolean(11)
                    || result.getBoolean(12) || result.getBoolean(13) || result.getBoolean(14)
                    || !"pg_catalog,public,pg_temp".equals(result.getString(15))
                    || result.next()) {
                throw new IllegalStateException("archive detacher identity is over-privileged");
            }
        }
    }

    private static void requireExactFunctions(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*) = 2
                   AND bool_and(p.oid IN (
                     to_regprocedure('public.elmpay_detach_archive_partition(text,uuid,text)'),
                     to_regprocedure('public.elmpay_observe_archive_partition_detach(text,uuid,text)')))
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
                throw new IllegalStateException("archive detacher function boundary is invalid");
            }
        }
    }

    private static void requireNoDirectDataCapability(Connection connection) throws SQLException {
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
                throw new IllegalStateException("archive detacher has direct data capability");
            }
        }
    }
}
