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
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import javax.sql.DataSource;

/** Checksum-bound, transactional schema migration runner. */
public final class DatabaseMigrator {
    private static final List<String> MIGRATIONS = List.of(
            "db/migration/V032__payment_runtime.sql",
            "db/migration/V012__event_delivery_runtime.sql",
            "db/migration/V023__audit_timestamp_anchor.sql",
            "db/migration/V024__tenant_project_registry.sql",
            "db/migration/V025__merchant_kyb_profile.sql",
            "db/migration/V028__versioned_routing_policy.sql",
            "db/migration/V030__merchant_onboarding_workflow.sql",
            "db/migration/V033__payment_action_receipts.sql",
            "db/migration/V034__durable_refund_runtime.sql",
            "db/migration/V035__payment_intent_metadata.sql",
            "db/migration/V036__payment_attempt_close.sql",
            "db/migration/V037__provider_webhook_inbox.sql",
            "db/migration/V038__business_webhook_delivery.sql",
            "db/migration/V039__payment_timeline_read_model.sql",
            "db/migration/V054__apple_pay_lifecycle.sql",
            "db/migration/V056__checkout_sessions.sql",
            "db/migration/V057__durable_payment_links.sql",
            "db/migration/V062__checkout_capability_health.sql",
            "db/migration/V066__durable_commerce_runtime.sql",
            "db/migration/V072__immutable_ledger.sql",
            "db/migration/V076__reconciliation.sql",
            "db/migration/V079__financial_runtime.sql",
            "db/migration/V100__provider_call_circuit.sql");
    private final DataSource dataSource;

    public DatabaseMigrator(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public void migrate() {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("""
                            CREATE TABLE IF NOT EXISTS elmpay_schema_history (
                                version text PRIMARY KEY,
                                checksum char(64) NOT NULL,
                                installed_at timestamptz NOT NULL
                            )
                            """);
                }
                for (String resource : MIGRATIONS) {
                    apply(connection, resource);
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("database migration failed", exception);
        }
    }

    static List<String> migrationResources() {
        return MIGRATIONS;
    }

    private static void apply(Connection connection, String resource) throws SQLException {
        String script = read(resource);
        String checksum = sha256(script);
        String existing = checksum(connection, resource);
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
                INSERT INTO elmpay_schema_history(version, checksum, installed_at)
                VALUES (?, ?, ?::timestamptz)
                """)) {
            statement.setString(1, resource);
            statement.setString(2, checksum);
            statement.setString(3, Instant.now().toString());
            statement.executeUpdate();
        }
    }

    private static String checksum(Connection connection, String version) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT checksum FROM elmpay_schema_history WHERE version = ? FOR UPDATE")) {
            statement.setString(1, version);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getString(1) : null;
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
