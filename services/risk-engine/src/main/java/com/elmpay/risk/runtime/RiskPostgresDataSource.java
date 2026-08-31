package com.elmpay.risk.runtime;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** PostgreSQL connection factory with non-overridable verify-full mTLS and mounted credentials. */
public final class RiskPostgresDataSource implements DataSource {
    static final String RUNTIME_DATABASE_ROLE = "elmpay_risk_engine";
    @FunctionalInterface
    interface ConnectionFactory {
        Connection open(String url, Properties properties) throws SQLException;
    }

    private final String url;
    private final String username;
    private final RiskMountedFiles.MountedPath passwordFile;
    private final RiskMountedFiles.MountedPath caFile;
    private final RiskMountedFiles.MountedPath certificateFile;
    private final RiskMountedFiles.MountedPath privateKeyFile;
    private final ConnectionFactory connections;
    private volatile int loginTimeout = 5;

    public static RiskPostgresDataSource fromEnvironment(Map<String, String> environment) {
        if (environment.containsKey("ELMPAY_RISK_DATABASE_PASSWORD")) {
            throw new IllegalStateException("database password environment values are forbidden");
        }
        return new RiskPostgresDataSource(required(environment, "ELMPAY_RISK_DATABASE_URL"),
                requireRuntimeUsername(required(environment, "ELMPAY_RISK_DATABASE_USERNAME")),
                RiskMountedFiles.configured(environment, "ELMPAY_RISK_DATABASE_PASSWORD_FILE"),
                RiskMountedFiles.configured(environment, "ELMPAY_RISK_DATABASE_CA_FILE"),
                RiskMountedFiles.configured(environment,
                        "ELMPAY_RISK_DATABASE_CLIENT_CERTIFICATE_FILE"),
                RiskMountedFiles.configured(environment,
                        "ELMPAY_RISK_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                DriverManager::getConnection);
    }

    RiskPostgresDataSource(String url, String username, Path passwordFile, Path caFile,
            Path certificateFile, Path privateKeyFile) {
        this(url, username, passwordFile, caFile, certificateFile, privateKeyFile,
                DriverManager::getConnection);
    }

    RiskPostgresDataSource(String url, String username, Path passwordFile, Path caFile,
            Path certificateFile, Path privateKeyFile, ConnectionFactory connections) {
        this(url, username, testMount(passwordFile, 8 * 1024),
                testMount(caFile, 2 * 1024 * 1024),
                testMount(certificateFile, 2 * 1024 * 1024),
                testMount(privateKeyFile, 64 * 1024),
                connections);
    }

    private RiskPostgresDataSource(String url, String username,
            RiskMountedFiles.MountedPath passwordFile, RiskMountedFiles.MountedPath caFile,
            RiskMountedFiles.MountedPath certificateFile,
            RiskMountedFiles.MountedPath privateKeyFile, ConnectionFactory connections) {
        this.url = validateUrl(url);
        this.username = requireRuntimeUsername(username);
        this.passwordFile = Objects.requireNonNull(passwordFile, "database password");
        this.caFile = Objects.requireNonNull(caFile, "database CA");
        this.certificateFile = Objects.requireNonNull(certificateFile,
                "database client certificate");
        this.privateKeyFile = Objects.requireNonNull(privateKeyFile,
                "database client private key");
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Connection getConnection() throws SQLException {
        Path pinnedCa = requireMounted(caFile, "database CA", 2 * 1024 * 1024);
        Path pinnedCertificate = requireMounted(certificateFile, "database client certificate",
                2 * 1024 * 1024);
        Path pinnedPrivateKey = requireMounted(privateKeyFile, "database client private key",
                64 * 1024);
        Properties properties = new Properties();
        properties.setProperty("user", username);
        properties.setProperty("password", password());
        properties.setProperty("ApplicationName", "elmpay-risk-engine");
        // Keep temporary objects behind the governed application schema so an accidental TEMP
        // re-grant cannot let a temporary object shadow an unqualified payment/risk relation.
        properties.setProperty("options", "-c search_path=pg_catalog,public,pg_temp");
        properties.setProperty("sslmode", "verify-full");
        properties.setProperty("sslrootcert", pinnedCa.toString());
        properties.setProperty("sslcert", pinnedCertificate.toString());
        properties.setProperty("sslkey", pinnedPrivateKey.toString());
        properties.setProperty("connectTimeout", Integer.toString(loginTimeout));
        properties.setProperty("loginTimeout", Integer.toString(loginTimeout));
        properties.setProperty("socketTimeout", "5");
        properties.setProperty("tcpKeepAlive", "true");
        try {
            return connections.open(url, properties);
        } finally {
            // The JDBC API requires immutable String properties, but the transient map need not
            // retain another reference after the synchronous connection attempt returns.
            properties.clear();
        }
    }

    private String password() throws SQLException {
        requireMounted(passwordFile, "database password", 8_192);
        byte[] encoded = null;
        try {
            encoded = RiskMountedFiles.read(passwordFile, 8_192);
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(encoded)).toString();
            value = value.endsWith("\r\n") ? value.substring(0, value.length() - 2)
                    : value.endsWith("\n") ? value.substring(0, value.length() - 1) : value;
            if (value.isBlank() || value.indexOf('\0') >= 0 || value.indexOf('\r') >= 0
                    || value.indexOf('\n') >= 0) {
                throw new SQLException("database password mount is malformed");
            }
            return value;
        } catch (IOException failure) {
            throw new SQLException("database password mount cannot be read", failure);
        } finally {
            if (encoded != null) java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    static Path requireMounted(RiskMountedFiles.MountedPath path, String label, long maximum)
            throws SQLException {
        try {
            return RiskMountedFiles.inspect(path, maximum);
        } catch (IOException | RuntimeException failure) {
            throw new SQLException(label + " mount cannot be inspected", failure);
        }
    }

    private static String validateUrl(String value) {
        if (value == null || !value.startsWith("jdbc:")) {
            throw new IllegalArgumentException("risk database URL must use JDBC PostgreSQL");
        }
        URI uri;
        try {
            uri = URI.create(value.substring(5));
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("risk database URL is malformed", failure);
        }
        int port = uri.getPort();
        if (!"postgresql".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || (port != -1 && (port < 1 || port > 65_535))
                || uri.getRawPath() == null || !uri.getRawPath().matches("/[A-Za-z0-9_-]{1,63}")) {
            throw new IllegalArgumentException("risk database URL must be a credential-free origin");
        }
        return value;
    }

    private static RiskMountedFiles.MountedPath testMount(Path path, long maximum) {
        Objects.requireNonNull(path, "path");
        Path absolute = path.toAbsolutePath().normalize();
        Path parent = Objects.requireNonNull(absolute.getParent(), "mount parent");
        return RiskMountedFiles.forTest(absolute, parent,
                absolute.getFileName().toString(), maximum);
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) throw new IllegalStateException(key + " is required");
        return value;
    }

    static String requireRuntimeUsername(String username) {
        if (!RUNTIME_DATABASE_ROLE.equals(username)) {
            throw new IllegalStateException(
                    "ELMPAY_RISK_DATABASE_USERNAME must use the dedicated risk runtime role");
        }
        return username;
    }

    @Override public Connection getConnection(String user, String password)
            throws SQLException { throw new SQLFeatureNotSupportedException("credential override forbidden"); }
    @Override public PrintWriter getLogWriter() { return null; }
    @Override public void setLogWriter(PrintWriter writer) throws SQLException {
        if (writer != null) throw new SQLFeatureNotSupportedException("JDBC logging forbidden");
    }
    @Override public void setLoginTimeout(int seconds) {
        if (seconds < 1 || seconds > 30) throw new IllegalArgumentException("timeout must be 1..30");
        loginTimeout = seconds;
    }
    @Override public int getLoginTimeout() { return loginTimeout; }
    @Override public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("no parent logger");
    }
    @Override public <T> T unwrap(Class<T> type) throws SQLException {
        if (type.isInstance(this)) return type.cast(this);
        throw new SQLException("unsupported wrapper");
    }
    @Override public boolean isWrapperFor(Class<?> type) { return type.isInstance(this); }
}
