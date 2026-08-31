package com.elmpay.webhook.ingress;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** PostgreSQL mTLS data source that reloads the read-only password mount per connection. */
public final class FileBackedWebhookPostgresDataSource implements DataSource {
    @FunctionalInterface
    interface ConnectionFactory {
        Connection open(String url, Properties properties) throws SQLException;
    }

    private static final int MAXIMUM_SECRET_BYTES = 8_192;
    private static final long MAXIMUM_TLS_FILE_BYTES = 2L * 1024L * 1024L;
    private final String url;
    private final String username;
    private final Path passwordFile;
    private final Path caFile;
    private final Path clientCertificateFile;
    private final Path clientPrivateKeyFile;
    private final ConnectionFactory connectionFactory;
    private volatile int loginTimeoutSeconds = 10;

    public FileBackedWebhookPostgresDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile) {
        this(url, username, passwordFile, caFile, clientCertificateFile, clientPrivateKeyFile,
                DriverManager::getConnection);
    }

    FileBackedWebhookPostgresDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile,
            ConnectionFactory connectionFactory) {
        this.url = databaseUrl(url);
        this.username = databaseUsername(username);
        this.passwordFile = absolute(passwordFile, "passwordFile");
        this.caFile = absolute(caFile, "caFile");
        this.clientCertificateFile = absolute(clientCertificateFile, "clientCertificateFile");
        this.clientPrivateKeyFile = absolute(clientPrivateKeyFile, "clientPrivateKeyFile");
        this.connectionFactory = Objects.requireNonNull(connectionFactory, "connectionFactory");
    }

    @Override
    public Connection getConnection() throws SQLException {
        requireReadOnlyMount(caFile, "database CA", MAXIMUM_TLS_FILE_BYTES);
        requireReadOnlyMount(clientCertificateFile, "database client certificate",
                MAXIMUM_TLS_FILE_BYTES);
        requireReadOnlyMount(clientPrivateKeyFile, "database client private key",
                MAXIMUM_TLS_FILE_BYTES);
        Properties properties = new Properties();
        properties.setProperty("user", username);
        properties.setProperty("password", mountedSecret(passwordFile));
        properties.setProperty("loginTimeout", Integer.toString(loginTimeoutSeconds));
        properties.setProperty("connectTimeout", Integer.toString(loginTimeoutSeconds));
        properties.setProperty("socketTimeout", "30");
        properties.setProperty("tcpKeepAlive", "true");
        properties.setProperty("ApplicationName", "elmpay-webhook-processor");
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
    public void setLogWriter(PrintWriter output) throws SQLException {
        if (output != null) {
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
    public <T> T unwrap(Class<T> type) throws SQLException {
        if (type.isInstance(this)) {
            return type.cast(this);
        }
        throw new SQLException("unsupported unwrap type");
    }

    @Override
    public boolean isWrapperFor(Class<?> type) {
        return type.isInstance(this);
    }

    static String mountedSecret(Path path) throws SQLException {
        Path resolved = requireReadOnlyMount(path, "database password", MAXIMUM_SECRET_BYTES);
        try {
            String value = Files.readString(resolved, StandardCharsets.UTF_8);
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
        } catch (IOException failure) {
            throw new SQLException("database password mount cannot be read", failure);
        }
    }

    private static Path requireReadOnlyMount(Path path, String label, long maximumBytes)
            throws SQLException {
        try {
            Path mountedDirectory = path.getParent().toRealPath();
            Path real = path.toRealPath();
            // Kubernetes projected Secret keys are symlinks into an atomically rotated ..data
            // directory. Permit only a target contained by the resolved mount directory.
            if (!real.startsWith(mountedDirectory)
                    || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)) {
                throw new SQLException(label + " mount is not a contained regular file");
            }
            long size = Files.size(real);
            if (size < 1 || size > maximumBytes) {
                throw new SQLException(label + " mount has an invalid size");
            }
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(real,
                        LinkOption.NOFOLLOW_LINKS);
                if (permissions.contains(PosixFilePermission.OWNER_WRITE)
                        || permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    throw new SQLException(label + " mount must be read-only");
                }
            } catch (UnsupportedOperationException ignored) {
                if (Files.isWritable(real)) {
                    throw new SQLException(label + " mount must be read-only");
                }
            }
            return real;
        } catch (IOException failure) {
            throw new SQLException(label + " mount cannot be inspected", failure);
        }
    }

    private static String databaseUrl(String value) {
        Objects.requireNonNull(value, "url");
        URI uri;
        try {
            if (!value.startsWith("jdbc:")) {
                throw new IllegalArgumentException("missing JDBC prefix");
            }
            uri = URI.create(value.substring("jdbc:".length()));
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("invalid PostgreSQL URL: malformed", malformed);
        }
        int port = uri.getPort();
        if (!"postgresql".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getHost().isBlank() || uri.getUserInfo() != null || uri.getQuery() != null
                || uri.getFragment() != null || (port != -1 && (port < 1 || port > 65_535))
                || uri.getRawPath() == null
                || !uri.getRawPath().matches("/[A-Za-z0-9_-]{1,63}")) {
            throw new IllegalArgumentException(
                    "invalid PostgreSQL URL: only an origin and database name are allowed");
        }
        return value;
    }

    private static String databaseUsername(String value) {
        Objects.requireNonNull(value, "username");
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{1,127}")) {
            throw new IllegalArgumentException("PostgreSQL username is invalid");
        }
        return value;
    }

    private static Path absolute(Path value, String field) {
        Path normalized = Objects.requireNonNull(value, field).normalize();
        if (!normalized.isAbsolute()) {
            throw new IllegalArgumentException(field + " must be absolute");
        }
        return normalized;
    }
}
