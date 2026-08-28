package com.elmpay.payment.provider;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL implementation that never derives expected money facts from the callback payload. */
public final class JdbcProviderRuntimeLookup implements ProviderRuntimeLookup {
    private static final String FACT_COLUMNS =
            "external_reference, provider_object_id, amount_minor, currency";
    private final DataSource dataSource;

    public JdbcProviderRuntimeLookup(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public PaymentFacts byBusinessReference(UUID tenantId, UUID providerAccountId,
            String provider, String businessReference) {
        requireReference(businessReference, "businessReference");
        String normalized = provider(provider);
        String sql = """
                SELECT DISTINCT pi.external_reference,
                       COALESCE((
                           SELECT a2.provider_transaction_id
                             FROM payment_attempt a2
                            WHERE a2.tenant_id = pi.tenant_id
                              AND a2.payment_intent_id = pi.id
                              AND a2.provider_account_id = ?::uuid
                              AND a2.provider = ?
                              AND a2.provider_transaction_id IS NOT NULL
                            ORDER BY a2.sequence DESC LIMIT 1
                       ), '') AS provider_object_id,
                       pi.amount_minor, pi.currency
                  FROM payment_intent pi
                 WHERE pi.tenant_id = ?::uuid
                   AND pi.external_reference = ?
                   AND EXISTS (
                       SELECT 1 FROM payment_attempt pa
                        WHERE pa.tenant_id = pi.tenant_id
                          AND pa.payment_intent_id = pi.id
                          AND pa.provider_account_id = ?::uuid
                          AND pa.provider = ?)
                 LIMIT 2
                """;
        return unique(tenantId, sql, statement -> {
            statement.setString(1, providerAccountId.toString());
            statement.setString(2, normalized);
            statement.setString(3, tenantId.toString());
            statement.setString(4, businessReference);
            statement.setString(5, providerAccountId.toString());
            statement.setString(6, normalized);
        });
    }

    @Override
    public PaymentFacts byProviderObject(UUID tenantId, UUID providerAccountId,
            String provider, String providerObjectId) {
        requireReference(providerObjectId, "providerObjectId");
        String normalized = provider(provider);
        String sql = """
                SELECT external_reference, provider_object_id, amount_minor, currency
                  FROM (
                    SELECT pi.external_reference,
                           pa.provider_transaction_id AS provider_object_id,
                           pi.amount_minor, pi.currency
                      FROM payment_attempt pa
                      JOIN payment_intent pi
                        ON pi.tenant_id = pa.tenant_id AND pi.id = pa.payment_intent_id
                     WHERE pa.tenant_id = ?::uuid
                       AND pa.provider_account_id = ?::uuid
                       AND pa.provider = ?
                       AND pa.provider_transaction_id = ?
                    UNION
                    SELECT pi.external_reference,
                           r.provider_refund_id AS provider_object_id,
                           r.amount_minor, r.currency
                      FROM refund r
                      JOIN payment_intent pi
                        ON pi.tenant_id = r.tenant_id AND pi.id = r.payment_intent_id
                     WHERE r.tenant_id = ?::uuid
                       AND r.provider_account_id = ?::uuid
                       AND r.provider = ?
                       AND r.provider_refund_id = ?
                  ) facts
                 LIMIT 2
                """;
        return unique(tenantId, sql, statement -> {
            statement.setString(1, tenantId.toString());
            statement.setString(2, providerAccountId.toString());
            statement.setString(3, normalized);
            statement.setString(4, providerObjectId);
            statement.setString(5, tenantId.toString());
            statement.setString(6, providerAccountId.toString());
            statement.setString(7, normalized);
            statement.setString(8, providerObjectId);
        });
    }

    @Override
    public String refundBusinessReference(UUID tenantId, UUID providerAccountId, String provider,
            String providerRefundId, String refundReference) {
        requireReference(providerRefundId, "providerRefundId");
        requireReference(refundReference, "refundReference");
        String normalized = provider(provider);
        String sql = """
                SELECT DISTINCT pi.external_reference
                  FROM refund r
                  JOIN payment_intent pi
                    ON pi.tenant_id = r.tenant_id AND pi.id = r.payment_intent_id
                 WHERE r.tenant_id = ?::uuid
                   AND r.provider_account_id = ?::uuid
                   AND r.provider = ?
                   AND (r.id::text = ? OR r.provider_refund_id = ?)
                 LIMIT 2
                """;
        List<String> results = read(tenantId, sql, statement -> {
            statement.setString(1, tenantId.toString());
            statement.setString(2, providerAccountId.toString());
            statement.setString(3, normalized);
            statement.setString(4, refundReference);
            statement.setString(5, providerRefundId);
        }, rows -> rows.getString(1));
        if (results.size() != 1) {
            throw new SecurityException("refund cannot be bound to one durable payment fact");
        }
        return results.getFirst();
    }

    private PaymentFacts unique(UUID tenantId, String sql, Binder binder) {
        List<PaymentFacts> results = read(tenantId, sql, binder, rows -> new PaymentFacts(
                rows.getString("external_reference"), rows.getString("provider_object_id"),
                rows.getLong("amount_minor"), rows.getString("currency")));
        if (results.size() != 1) {
            throw new SecurityException("provider object cannot be bound to one durable payment fact");
        }
        return results.getFirst();
    }

    private <T> List<T> read(UUID tenantId, String sql, Binder binder, Mapper<T> mapper) {
        Objects.requireNonNull(tenantId, "tenantId");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                List<T> results = new ArrayList<>();
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    binder.bind(statement);
                    try (ResultSet rows = statement.executeQuery()) {
                        while (rows.next()) {
                            results.add(mapper.map(rows));
                        }
                    }
                }
                connection.commit();
                return List.copyOf(results);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("provider fact lookup failed closed", exception);
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static String provider(String value) {
        String normalized = Objects.requireNonNull(value, "provider").toLowerCase(Locale.ROOT);
        if (!normalized.matches("[a-z][a-z0-9_]{1,31}")) {
            throw new IllegalArgumentException("provider is invalid");
        }
        return normalized;
    }

    private static void requireReference(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 256
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    @FunctionalInterface
    private interface Mapper<T> {
        T map(ResultSet rows) throws SQLException;
    }
}
