package com.elmpay.payment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/** Registers the immutable server-owned money fact for a full or partial capture attempt. */
public final class ProviderEffectExpectationService {
    private static final String LOCK_SOURCE_SQL = """
            SELECT pi.external_reference, pi.amount_minor, pi.captured_amount_minor, pi.currency,
                   pa.operation, pa.provider, pa.provider_account_id
              FROM payment_intent pi
              JOIN payment_attempt pa
                ON pa.tenant_id = pi.tenant_id AND pa.payment_intent_id = pi.id
              JOIN provider_account account
                ON account.tenant_id = pi.tenant_id
               AND account.project_id = pi.project_id
               AND account.merchant_id = pi.merchant_id
               AND account.id = pa.provider_account_id
               AND account.provider = pa.provider
             WHERE pi.tenant_id = ?::uuid AND pi.project_id = ?::uuid
               AND pi.id = ?::uuid AND pa.id = ?::uuid
               AND pa.provider_account_id = ?::uuid AND pa.provider = ?
             FOR UPDATE OF pi, pa
            """;
    private static final String INSERT_SQL = """
            INSERT INTO provider_effect_expectation
              (tenant_id, project_id, payment_intent_id, payment_attempt_id,
               provider_account_id, provider, expected_delta_minor, currency,
               business_order_digest, created_at)
            VALUES (?::uuid, ?::uuid, ?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, payment_attempt_id) DO NOTHING
            """;
    private static final String REPLAY_SQL = """
            SELECT project_id, payment_intent_id, provider_account_id, provider,
                   expected_delta_minor, currency, business_order_digest, created_at
              FROM provider_effect_expectation
             WHERE tenant_id = ?::uuid AND payment_attempt_id = ?::uuid
            """;

    public record Registration(UUID paymentAttemptId, boolean replay) {
        public Registration {
            Objects.requireNonNull(paymentAttemptId, "paymentAttemptId");
        }
    }

    /** A permanent conflict: the same attempt cannot be rebound to different money facts. */
    public static final class ExpectationConflictException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ExpectationConflictException(String message) {
            super(message);
        }
    }

    /**
     * Registers inside the caller-owned JDBC transaction. This method never commits, rolls back,
     * changes tenant RLS, or derives an amount/reference from a callback.
     */
    public Registration registerCapture(Connection connection, UUID tenantId, UUID projectId,
            UUID intentId, UUID attemptId, UUID providerAccountId, String provider,
            long expectedDeltaMinor, String currency, String businessOrderDigest,
            Instant createdAt) {
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(attemptId, "attemptId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        Objects.requireNonNull(createdAt, "createdAt");
        String normalizedProvider = provider(provider);
        String normalizedCurrency = currency(currency);
        requireDigest(businessOrderDigest, "businessOrderDigest");
        if (expectedDeltaMinor <= 0) {
            throw new IllegalArgumentException("expectedDeltaMinor must be positive");
        }
        try {
            if (connection.getAutoCommit()) {
                throw new IllegalStateException(
                        "provider effect expectation requires a caller-owned transaction");
            }
            Source source = lockSource(connection, tenantId, projectId, intentId, attemptId,
                    providerAccountId, normalizedProvider);
            if (!"capture".equals(source.operation())
                    || !normalizedProvider.equals(source.provider())
                    || !providerAccountId.equals(source.providerAccountId())) {
                throw conflict("capture attempt is not bound to the requested provider account");
            }
            if (!normalizedCurrency.equals(source.currency())
                    || !businessOrderDigest.equals(sha256(source.externalReference()))) {
                throw conflict("capture expectation does not match immutable payment facts");
            }
            long remaining = Math.subtractExact(source.amountMinor(), source.capturedAmountMinor());
            if (expectedDeltaMinor > remaining) {
                throw conflict("capture expectation exceeds the immutable uncaptured amount");
            }
            try (PreparedStatement statement = connection.prepareStatement(INSERT_SQL)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                statement.setString(3, intentId.toString());
                statement.setString(4, attemptId.toString());
                statement.setString(5, providerAccountId.toString());
                statement.setString(6, normalizedProvider);
                statement.setLong(7, expectedDeltaMinor);
                statement.setString(8, normalizedCurrency);
                statement.setString(9, businessOrderDigest);
                statement.setTimestamp(10, Timestamp.from(createdAt));
                if (statement.executeUpdate() == 1) {
                    return new Registration(attemptId, false);
                }
            }
            requireSameReplay(connection, tenantId, projectId, intentId, attemptId,
                    providerAccountId, normalizedProvider, expectedDeltaMinor,
                    normalizedCurrency, businessOrderDigest);
            return new Registration(attemptId, true);
        } catch (SQLException failure) {
            throw new IllegalStateException("capture expectation could not be registered", failure);
        }
    }

    private static Source lockSource(Connection connection, UUID tenantId, UUID projectId,
            UUID intentId, UUID attemptId, UUID providerAccountId, String provider)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(LOCK_SOURCE_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, projectId.toString());
            statement.setString(3, intentId.toString());
            statement.setString(4, attemptId.toString());
            statement.setString(5, providerAccountId.toString());
            statement.setString(6, provider);
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) {
                    throw conflict("capture attempt cannot be uniquely bound to payment facts");
                }
                Source result = new Source(row.getString("external_reference"),
                        row.getLong("amount_minor"), row.getLong("captured_amount_minor"),
                        row.getString("currency"), row.getString("operation"),
                        row.getString("provider"),
                        row.getObject("provider_account_id", UUID.class));
                if (row.next()) {
                    throw conflict("capture attempt binding is ambiguous");
                }
                return result;
            }
        }
    }

    private static void requireSameReplay(Connection connection, UUID tenantId, UUID projectId,
            UUID intentId, UUID attemptId, UUID providerAccountId, String provider,
            long expectedDeltaMinor, String currency, String businessOrderDigest)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(REPLAY_SQL)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, attemptId.toString());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()
                        || !projectId.equals(row.getObject("project_id", UUID.class))
                        || !intentId.equals(row.getObject("payment_intent_id", UUID.class))
                        || !providerAccountId.equals(
                                row.getObject("provider_account_id", UUID.class))
                        || !provider.equals(row.getString("provider"))
                        || expectedDeltaMinor != row.getLong("expected_delta_minor")
                        || !currency.equals(row.getString("currency"))
                        || !businessOrderDigest.equals(row.getString("business_order_digest"))
                        || row.next()) {
                    throw conflict("capture attempt expectation conflicts with its first write");
                }
            }
        }
    }

    public static String businessOrderDigest(String canonicalBusinessOrder) {
        if (canonicalBusinessOrder == null || canonicalBusinessOrder.isBlank()
                || canonicalBusinessOrder.length() > 160
                || canonicalBusinessOrder.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException("canonicalBusinessOrder has an invalid format");
        }
        return sha256(canonicalBusinessOrder);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static String provider(String value) {
        String normalized = Objects.requireNonNull(value, "provider").toLowerCase(Locale.ROOT);
        if (!normalized.matches("(?:wechat|alipay|stripe|paypal)")) {
            throw new IllegalArgumentException("provider is not callback-capable");
        }
        return normalized;
    }

    private static String currency(String value) {
        String normalized = Objects.requireNonNull(value, "currency").toUpperCase(Locale.ROOT);
        if (!normalized.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency has an invalid format");
        }
        return normalized;
    }

    private static void requireDigest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static ExpectationConflictException conflict(String message) {
        return new ExpectationConflictException(message);
    }

    private record Source(String externalReference, long amountMinor, long capturedAmountMinor,
            String currency, String operation, String provider, UUID providerAccountId) {
    }
}
