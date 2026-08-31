package com.elmpay.gateway;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;
import javax.sql.DataSource;

/**
 * PostgreSQL data source with a non-overridable TLS policy and rotated mounted credentials.
 * Pooling is supplied by the deployment environment.
 */
public final class DriverManagerDataSource implements DataSource {
    @FunctionalInterface
    interface ConnectionFactory {
        Connection open(String url, Properties properties) throws SQLException;
    }

    private static final int MAXIMUM_SECRET_BYTES = 8_192;
    private static final long MAXIMUM_TLS_FILE_BYTES = 2L * 1024L * 1024L;
    private static final Set<PosixFilePermission> WRITE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_WRITE);

    private final String url;
    private final String username;
    private final Path passwordFile;
    private final Path caFile;
    private final Path clientCertificateFile;
    private final Path clientPrivateKeyFile;
    private final String applicationName;
    private final ConnectionFactory connectionFactory;
    private volatile int loginTimeoutSeconds = 10;

    public static DriverManagerDataSource fromEnvironment(Map<String, String> environment,
            String applicationName) {
        Objects.requireNonNull(environment, "environment");
        if (environment.containsKey("ELMPAY_DATABASE_PASSWORD")) {
            throw new IllegalStateException(
                    "ELMPAY_DATABASE_PASSWORD is forbidden; use the read-only password mount");
        }
        return new DriverManagerDataSource(
                required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USERNAME"),
                absolute(environment, "ELMPAY_DATABASE_PASSWORD_FILE"),
                absolute(environment, "ELMPAY_DATABASE_CA_FILE"),
                absolute(environment, "ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE"),
                absolute(environment, "ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                applicationName);
    }

    public DriverManagerDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile,
            String applicationName) {
        this(url, username, passwordFile, caFile, clientCertificateFile, clientPrivateKeyFile,
                applicationName, DriverManager::getConnection);
    }

    DriverManagerDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile,
            String applicationName, ConnectionFactory connectionFactory) {
        this.url = databaseUrl(url);
        this.username = databaseUsername(username);
        this.passwordFile = absolute(passwordFile, "database password file");
        this.caFile = absolute(caFile, "database CA file");
        this.clientCertificateFile = absolute(clientCertificateFile,
                "database client certificate file");
        this.clientPrivateKeyFile = absolute(clientPrivateKeyFile,
                "database client private-key file");
        this.applicationName = require(applicationName, "database application name");
        if (!applicationName.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("database application name is invalid");
        }
        this.connectionFactory = Objects.requireNonNull(connectionFactory, "connectionFactory");
    }

    @Override
    public Connection getConnection() throws SQLException {
        requireReadOnlyRegular(caFile, "database CA", MAXIMUM_TLS_FILE_BYTES);
        requireReadOnlyRegular(clientCertificateFile, "database client certificate",
                MAXIMUM_TLS_FILE_BYTES);
        requireReadOnlyRegular(clientPrivateKeyFile, "database client private key",
                MAXIMUM_TLS_FILE_BYTES);
        Properties properties = new Properties();
        properties.setProperty("user", username);
        properties.setProperty("password", mountedSecret(passwordFile));
        properties.setProperty("loginTimeout", Integer.toString(loginTimeoutSeconds));
        properties.setProperty("connectTimeout", Integer.toString(loginTimeoutSeconds));
        properties.setProperty("socketTimeout", "30");
        properties.setProperty("tcpKeepAlive", "true");
        properties.setProperty("ApplicationName", applicationName);
        properties.setProperty("options", "-c search_path=pg_catalog,public,pg_temp");
        properties.setProperty("sslmode", "verify-full");
        properties.setProperty("sslrootcert", caFile.toString());
        properties.setProperty("sslcert", clientCertificateFile.toString());
        properties.setProperty("sslkey", clientPrivateKeyFile.toString());
        return connectionFactory.open(url, properties);
    }

    @Override
    public Connection getConnection(String suppliedUsername, String suppliedPassword)
            throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "callers cannot override the mounted workload credential");
    }

    @Override
    public PrintWriter getLogWriter() {
        return null;
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
        if (out != null) {
            throw new SQLFeatureNotSupportedException(
                    "JDBC driver logging could expose connection metadata");
        }
    }

    @Override
    public void setLoginTimeout(int seconds) {
        if (seconds < 1 || seconds > 60) {
            throw new IllegalArgumentException("login timeout must be 1..60 seconds");
        }
        loginTimeoutSeconds = seconds;
    }

    @Override
    public int getLoginTimeout() {
        return loginTimeoutSeconds;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("no parent logger");
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("data source does not wrap " + iface.getName());
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
        return iface.isInstance(this);
    }

    private static String require(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    static String mountedSecret(Path path) throws SQLException {
        Path resolved = requireReadOnlyRegular(path, "database password", MAXIMUM_SECRET_BYTES);
        byte[] encoded = null;
        try {
            encoded = Files.readAllBytes(resolved);
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString();
            if (value.endsWith("\r\n")) {
                value = value.substring(0, value.length() - 2);
            } else if (value.endsWith("\n")) {
                value = value.substring(0, value.length() - 1);
            }
            if (value.isBlank() || value.length() > MAXIMUM_SECRET_BYTES
                    || value.chars().anyMatch(character -> character == 0 || character == '\r'
                            || character == '\n')) {
                throw new SQLException("database password mount has an invalid value");
            }
            return value;
        } catch (CharacterCodingException failure) {
            throw new SQLException("database password mount is not strict UTF-8", failure);
        } catch (IOException failure) {
            throw new SQLException("database password mount cannot be read", failure);
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }

    private static Path requireReadOnlyRegular(Path path, String label, long maximumBytes)
            throws SQLException {
        try {
            Path mountParent = path.getParent().toRealPath();
            Path resolved = path.toRealPath();
            if (!resolved.startsWith(mountParent)) {
                throw new SQLException(label + " mount escapes its controlled directory");
            }
            if (!Files.isRegularFile(resolved)) {
                throw new SQLException(label + " mount is not a regular file");
            }
            long size = Files.size(resolved);
            if (size < 1 || size > maximumBytes) {
                throw new SQLException(label + " mount has an invalid size");
            }
            try {
                if (Files.getPosixFilePermissions(resolved).stream()
                        .anyMatch(WRITE_PERMISSIONS::contains)) {
                    throw new SQLException(label + " mount must be read-only");
                }
            } catch (UnsupportedOperationException ignored) {
                if (Files.isWritable(resolved)) {
                    throw new SQLException(label + " mount must be read-only");
                }
            }
            return resolved;
        } catch (IOException failure) {
            throw new SQLException(label + " mount cannot be inspected", failure);
        }
    }

    private static String databaseUrl(String value) {
        String candidate = require(value, "database URL");
        URI uri;
        try {
            if (!candidate.startsWith("jdbc:")) {
                throw new IllegalArgumentException("missing JDBC prefix");
            }
            uri = URI.create(candidate.substring("jdbc:".length()));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("database URL is malformed", invalid);
        }
        int port = uri.getPort();
        if (!"postgresql".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getHost().isBlank() || uri.getUserInfo() != null || uri.getQuery() != null
                || uri.getFragment() != null || (port != -1 && (port < 1 || port > 65_535))
                || uri.getRawPath() == null
                || !uri.getRawPath().matches("/[A-Za-z0-9_-]{1,63}")) {
            throw new IllegalArgumentException(
                    "database URL must be a credential-free PostgreSQL origin and database name");
        }
        return candidate;
    }

    private static String databaseUsername(String value) {
        String candidate = require(value, "database username");
        if (!candidate.matches("[A-Za-z0-9][A-Za-z0-9._:-]{1,127}")) {
            throw new IllegalArgumentException("database username is invalid");
        }
        return candidate;
    }

    private static Path absolute(Map<String, String> environment, String name) {
        return absolute(Path.of(required(environment, name)), name);
    }

    private static Path absolute(Path value, String name) {
        Objects.requireNonNull(value, name);
        Path normalized = value.normalize();
        if (!normalized.isAbsolute() || normalized.toString().indexOf('\0') >= 0) {
            throw new IllegalArgumentException(name + " must be an absolute path");
        }
        return normalized;
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for PostgreSQL runtime");
        }
        return value;
    }
}
