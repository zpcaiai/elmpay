package com.elmpay.connectors.applepay;

import java.net.IDN;
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
import javax.sql.DataSource;

/** Durable Apple Pay domain, certificate and merchant-token lifecycle policy. */
public final class DataSourceApplePayLifecycle implements ApplePayAdapter.LifecyclePolicy {
    private final DataSource dataSource;

    public DataSourceApplePayLifecycle(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public void registerDomain(String tenantId, String merchantAccountId, String domain,
            byte[] expectedAssociationFile, Instant now) {
        String normalized = normalizeDomain(domain);
        validateIds(tenantId, merchantAccountId);
        Objects.requireNonNull(expectedAssociationFile, "expectedAssociationFile");
        Objects.requireNonNull(now, "now");
        if (expectedAssociationFile.length < 16 || expectedAssociationFile.length > 65_536) {
            throw new IllegalArgumentException("invalid Apple domain association file size");
        }
        String digest = sha256(expectedAssociationFile);
        String sql = "INSERT INTO apple_pay_domain "
                + "(tenant_id, merchant_account_id, domain_name, association_sha256, status, created_at, updated_at) "
                + "VALUES (?, ?, ?, ?, 'PENDING', ?, ?) "
                + "ON CONFLICT (tenant_id, merchant_account_id, domain_name) DO UPDATE SET "
                + "association_sha256=EXCLUDED.association_sha256, status='PENDING', verified_at=NULL, "
                + "updated_at=EXCLUDED.updated_at";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenantId);
                statement.setString(2, merchantAccountId);
                statement.setString(3, normalized);
                statement.setString(4, digest);
                statement.setTimestamp(5, Timestamp.from(now));
                statement.setTimestamp(6, Timestamp.from(now));
                statement.executeUpdate();
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to register Apple Pay domain", exception);
        }
    }

    public void verifyDomain(String tenantId, String merchantAccountId, String domain,
            byte[] servedAssociationFile, Instant now) {
        String normalized = normalizeDomain(domain);
        validateIds(tenantId, merchantAccountId);
        Objects.requireNonNull(servedAssociationFile, "servedAssociationFile");
        Objects.requireNonNull(now, "now");
        String supplied = sha256(servedAssociationFile);
        String sql = "UPDATE apple_pay_domain SET status='VERIFIED', verified_at=?, updated_at=? "
                + "WHERE tenant_id=? AND merchant_account_id=? AND domain_name=? "
                + "AND association_sha256=?";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setTimestamp(1, Timestamp.from(now));
                statement.setTimestamp(2, Timestamp.from(now));
                statement.setString(3, tenantId);
                statement.setString(4, merchantAccountId);
                statement.setString(5, normalized);
                statement.setString(6, supplied);
                if (statement.executeUpdate() != 1) {
                    throw new SecurityException("Apple domain association digest mismatch or unknown domain");
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to verify Apple Pay domain", exception);
        }
    }

    public void rotateCertificate(String tenantId, String merchantAccountId, String certificateVersion,
            String privateKeyReference, Instant validFrom, Instant validUntil, Instant now) {
        validateIds(tenantId, merchantAccountId);
        requireId(certificateVersion, "certificateVersion");
        requireSecretReference(privateKeyReference);
        Objects.requireNonNull(validFrom, "validFrom");
        Objects.requireNonNull(validUntil, "validUntil");
        Objects.requireNonNull(now, "now");
        if (!validUntil.isAfter(validFrom) || !validUntil.isAfter(now)) {
            throw new IllegalArgumentException("invalid certificate validity window");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try {
                Instant currentExpiry = currentCertificateExpiry(connection, tenantId, merchantAccountId);
                if (currentExpiry != null && validFrom.isAfter(currentExpiry)) {
                    throw new IllegalArgumentException("certificate rotation has no overlap");
                }
                try (PreparedStatement retire = connection.prepareStatement(
                        "UPDATE apple_pay_certificate SET status='OVERLAP', updated_at=? "
                                + "WHERE tenant_id=? AND merchant_account_id=? AND status='ACTIVE'")) {
                    retire.setTimestamp(1, Timestamp.from(now));
                    retire.setString(2, tenantId);
                    retire.setString(3, merchantAccountId);
                    retire.executeUpdate();
                }
                try (PreparedStatement insert = connection.prepareStatement(
                        "INSERT INTO apple_pay_certificate "
                                + "(tenant_id, merchant_account_id, certificate_version, private_key_ref, "
                                + "valid_from, valid_until, status, created_at, updated_at) "
                                + "VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)")) {
                    insert.setString(1, tenantId);
                    insert.setString(2, merchantAccountId);
                    insert.setString(3, certificateVersion);
                    insert.setString(4, privateKeyReference);
                    insert.setTimestamp(5, Timestamp.from(validFrom));
                    insert.setTimestamp(6, Timestamp.from(validUntil));
                    insert.setTimestamp(7, Timestamp.from(now));
                    insert.setTimestamp(8, Timestamp.from(now));
                    insert.executeUpdate();
                }
                connection.commit();
            } catch (RuntimeException | SQLException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to rotate Apple Pay certificate", exception);
        }
    }

    public void registerMerchantToken(String tenantId, String merchantAccountId,
            String merchantTokenReference, Instant now) {
        validateIds(tenantId, merchantAccountId);
        requireTokenReference(merchantTokenReference);
        Objects.requireNonNull(now, "now");
        String sql = "INSERT INTO apple_pay_merchant_token "
                + "(tenant_id, merchant_account_id, token_reference_hash, status, created_at, updated_at) "
                + "VALUES (?, ?, ?, 'ACTIVE', ?, ?) ON CONFLICT "
                + "(tenant_id, merchant_account_id, token_reference_hash) DO UPDATE SET "
                + "status='ACTIVE', updated_at=EXCLUDED.updated_at";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenantId);
                statement.setString(2, merchantAccountId);
                statement.setString(3, sha256(merchantTokenReference.getBytes(
                        java.nio.charset.StandardCharsets.UTF_8)));
                statement.setTimestamp(4, Timestamp.from(now));
                statement.setTimestamp(5, Timestamp.from(now));
                statement.executeUpdate();
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to register Apple Pay merchant token", exception);
        }
    }

    public void revokeMerchantToken(String tenantId, String merchantAccountId,
            String merchantTokenReference, Instant now) {
        validateIds(tenantId, merchantAccountId);
        requireTokenReference(merchantTokenReference);
        Objects.requireNonNull(now, "now");
        String sql = "UPDATE apple_pay_merchant_token SET status='REVOKED', updated_at=? "
                + "WHERE tenant_id=? AND merchant_account_id=? AND token_reference_hash=?";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setTimestamp(1, Timestamp.from(now));
                statement.setString(2, tenantId);
                statement.setString(3, merchantAccountId);
                statement.setString(4, sha256(merchantTokenReference.getBytes(
                        java.nio.charset.StandardCharsets.UTF_8)));
                if (statement.executeUpdate() != 1) {
                    throw new IllegalArgumentException("unknown merchant token reference");
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to revoke Apple Pay merchant token", exception);
        }
    }

    @Override
    public ApplePayAdapter.Authorization authorize(String tenantId, String merchantAccountId,
            String domain, String merchantTokenReference, Instant at) {
        String normalized = normalizeDomain(domain);
        validateIds(tenantId, merchantAccountId);
        Objects.requireNonNull(at, "at");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            ApplePayAdapter.Authorization result;
            if (!domainVerified(connection, tenantId, merchantAccountId, normalized)) {
                result = new ApplePayAdapter.Authorization(ApplePayAdapter.Capability.DOMAIN_NOT_VERIFIED, "");
            } else {
                String certificateVersion = activeCertificate(connection, tenantId, merchantAccountId, at);
                if (certificateVersion == null) {
                    result = new ApplePayAdapter.Authorization(
                            ApplePayAdapter.Capability.CERTIFICATE_UNAVAILABLE, "");
                } else if (merchantTokenReference != null && !merchantTokenReference.isBlank()
                        && !merchantTokenActive(connection, tenantId, merchantAccountId,
                                merchantTokenReference)) {
                    result = new ApplePayAdapter.Authorization(ApplePayAdapter.Capability.TOKEN_REVOKED,
                            certificateVersion);
                } else {
                    result = new ApplePayAdapter.Authorization(ApplePayAdapter.Capability.AVAILABLE,
                            certificateVersion);
                }
            }
            connection.commit();
            return result;
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to evaluate Apple Pay lifecycle", exception);
        }
    }

    private static Instant currentCertificateExpiry(Connection connection, String tenantId,
            String merchantAccountId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT valid_until FROM apple_pay_certificate WHERE tenant_id=? "
                        + "AND merchant_account_id=? AND status='ACTIVE' ORDER BY valid_until DESC LIMIT 1")) {
            statement.setString(1, tenantId);
            statement.setString(2, merchantAccountId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getTimestamp(1).toInstant() : null;
            }
        }
    }

    private static boolean domainVerified(Connection connection, String tenantId,
            String merchantAccountId, String domain) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM apple_pay_domain WHERE tenant_id=? AND merchant_account_id=? "
                        + "AND domain_name=? AND status='VERIFIED'")) {
            statement.setString(1, tenantId);
            statement.setString(2, merchantAccountId);
            statement.setString(3, domain);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static String activeCertificate(Connection connection, String tenantId,
            String merchantAccountId, Instant at) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT certificate_version FROM apple_pay_certificate WHERE tenant_id=? "
                        + "AND merchant_account_id=? AND status IN ('ACTIVE','OVERLAP') "
                        + "AND valid_from<=? AND valid_until>? ORDER BY valid_from DESC LIMIT 1")) {
            statement.setString(1, tenantId);
            statement.setString(2, merchantAccountId);
            statement.setTimestamp(3, Timestamp.from(at));
            statement.setTimestamp(4, Timestamp.from(at));
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1) : null;
            }
        }
    }

    private static boolean merchantTokenActive(Connection connection, String tenantId,
            String merchantAccountId, String tokenReference) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM apple_pay_merchant_token WHERE tenant_id=? AND merchant_account_id=? "
                        + "AND token_reference_hash=? AND status='ACTIVE'")) {
            statement.setString(1, tenantId);
            statement.setString(2, merchantAccountId);
            statement.setString(3, sha256(tokenReference.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static String normalizeDomain(String domain) {
        if (domain == null || domain.isBlank() || domain.contains("*") || domain.contains("/")
                || domain.contains(":")) {
            throw new IllegalArgumentException("invalid Apple Pay domain");
        }
        String normalized = IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        if (normalized.equals("localhost") || normalized.endsWith(".localhost")
                || !normalized.contains(".") || normalized.matches("[0-9.]+")
                || normalized.length() > 253) {
            throw new IllegalArgumentException("invalid Apple Pay domain");
        }
        return normalized;
    }

    private static void setTenant(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId);
            statement.execute();
        }
    }

    private static void validateIds(String tenantId, String merchantAccountId) {
        requireId(tenantId, "tenantId");
        requireId(merchantAccountId, "merchantAccountId");
    }

    private static void requireId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireSecretReference(String value) {
        if (value == null || !value.matches("(?:kms|hsm|vault)://[A-Za-z0-9/_:.-]{8,256}")) {
            throw new IllegalArgumentException("privateKeyReference must be a KMS/HSM/Vault reference");
        }
    }

    private static void requireTokenReference(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{16,256}")) {
            throw new IllegalArgumentException("invalid PSP merchant token reference");
        }
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
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
