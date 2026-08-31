package com.elmpay.scheduler;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** PostgreSQL data source with immutable transport policy and rotation-safe secret mounts. */
public final class FileBackedPostgresDataSource implements DataSource {
    @FunctionalInterface
    interface ConnectionFactory {
        Connection open(String url, Properties properties) throws SQLException;
    }

    private enum MountedKind {
        PASSWORD(1, 8_192), CA_CERTIFICATE(64, 1_048_576), CLIENT_CERTIFICATE(64, 1_048_576),
        PRIVATE_KEY(64, 262_144);

        private final long minimumBytes;
        private final long maximumBytes;

        MountedKind(long minimumBytes, long maximumBytes) {
            this.minimumBytes = minimumBytes;
            this.maximumBytes = maximumBytes;
        }
    }

    private record VerifiedMount(Path realPath, byte[] bytes) {}

    private static final Set<PosixFilePermission> WRITE_PERMISSIONS = EnumSet.of(
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_WRITE,
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

    public FileBackedPostgresDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile) {
        this(url, username, passwordFile, caFile, clientCertificateFile, clientPrivateKeyFile,
                "elmpay-worker-scheduler", DriverManager::getConnection);
    }

    public FileBackedPostgresDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile,
            String applicationName) {
        this(url, username, passwordFile, caFile, clientCertificateFile, clientPrivateKeyFile,
                requireApplicationName(applicationName), DriverManager::getConnection);
    }

    FileBackedPostgresDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile,
            ConnectionFactory connectionFactory) {
        this(url, username, passwordFile, caFile, clientCertificateFile, clientPrivateKeyFile,
                "elmpay-worker-scheduler", connectionFactory);
    }

    FileBackedPostgresDataSource(String url, String username, Path passwordFile,
            Path caFile, Path clientCertificateFile, Path clientPrivateKeyFile,
            String applicationName, ConnectionFactory connectionFactory) {
        this.url = requirePostgresUrl(url);
        this.username = requireUsername(username);
        this.passwordFile = mountedPath(passwordFile, "passwordFile");
        this.caFile = mountedPath(caFile, "caFile");
        this.clientCertificateFile = mountedPath(clientCertificateFile,
                "clientCertificateFile");
        this.clientPrivateKeyFile = mountedPath(clientPrivateKeyFile,
                "clientPrivateKeyFile");
        this.applicationName = requireApplicationName(applicationName);
        this.connectionFactory = Objects.requireNonNull(connectionFactory, "connectionFactory");
    }

    @Override
    public Connection getConnection() throws SQLException {
        // Resolve and validate on every connection. A Kubernetes ..data rotation is therefore
        // observed by the next connection, while this connection is pinned to one verified inode.
        VerifiedMount password = null;
        VerifiedMount ca = null;
        VerifiedMount certificate = null;
        VerifiedMount privateKey = null;
        Properties properties = null;
        try {
            password = verifyMount(passwordFile, MountedKind.PASSWORD);
            ca = verifyMount(caFile, MountedKind.CA_CERTIFICATE);
            certificate = verifyMount(clientCertificateFile,
                    MountedKind.CLIENT_CERTIFICATE);
            privateKey = verifyMount(clientPrivateKeyFile, MountedKind.PRIVATE_KEY);
            validatePem(ca, "CERTIFICATE", "database CA");
            validatePem(certificate, "CERTIFICATE", "database client certificate");
            validatePrivateKey(privateKey);

            properties = new Properties();
            properties.setProperty("user", username);
            // java.sql.Properties requires a String password. The unavoidable String is scoped
            // to this call; every mutable source buffer is wiped in the finally block.
            properties.setProperty("password", password(password.bytes()));
            properties.setProperty("loginTimeout", Integer.toString(loginTimeoutSeconds));
            properties.setProperty("connectTimeout", Integer.toString(loginTimeoutSeconds));
            properties.setProperty("socketTimeout", "30");
            properties.setProperty("tcpKeepAlive", "true");
            properties.setProperty("ApplicationName", applicationName);
            properties.setProperty("options", "-c search_path=pg_catalog,public,pg_temp");
            properties.setProperty("sslmode", "verify-full");
            properties.setProperty("sslrootcert", ca.realPath().toString());
            properties.setProperty("sslcert", certificate.realPath().toString());
            properties.setProperty("sslkey", privateKey.realPath().toString());
            return connectionFactory.open(url, properties);
        } finally {
            if (properties != null) {
                properties.clear();
            }
            wipe(password);
            wipe(ca);
            wipe(certificate);
            wipe(privateKey);
        }
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

    /** Reads a password mount through the same bounded, read-only, non-escaping policy. */
    public static String mountedSecret(Path path) throws SQLException {
        VerifiedMount mount = verifyMount(mountedPath(path, "path"), MountedKind.PASSWORD);
        try {
            return password(mount.bytes());
        } finally {
            wipe(mount);
        }
    }

    static String requirePostgresUrl(String value) {
        Objects.requireNonNull(value, "url");
        if (value.length() > 2_048 || !value.startsWith("jdbc:postgresql://")) {
            throw new IllegalArgumentException("invalid PostgreSQL JDBC URL");
        }
        final URI uri;
        try {
            uri = new URI(value.substring("jdbc:".length()));
        } catch (URISyntaxException failure) {
            throw new IllegalArgumentException("invalid PostgreSQL JDBC URL", failure);
        }
        String host = uri.getHost();
        String path = uri.getRawPath();
        if (!"postgresql".equals(uri.getScheme()) || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null
                || host == null || !validHost(host) || uri.getPort() < 1
                || uri.getPort() > 65_535 || path == null
                || !path.matches("/[A-Za-z0-9][A-Za-z0-9_-]{0,62}")) {
            throw new IllegalArgumentException(
                    "PostgreSQL JDBC URL requires one host, explicit port and database name; "
                            + "userinfo, query, fragment and TLS overrides are forbidden");
        }
        return value;
    }

    private static boolean validHost(String host) {
        if (host.indexOf(':') >= 0) {
            return host.matches("[0-9A-Fa-f:]{2,45}") && !host.contains(":::");
        }
        return host.length() <= 253 && host.matches("[A-Za-z0-9.-]+")
                && !host.startsWith(".") && !host.endsWith(".") && !host.contains("..")
                && java.util.Arrays.stream(host.split("\\."))
                        .allMatch(label -> !label.isEmpty() && label.length() <= 63
                                && !label.startsWith("-") && !label.endsWith("-"));
    }

    private static String requireUsername(String value) {
        Objects.requireNonNull(value, "username");
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{1,127}")) {
            throw new IllegalArgumentException("invalid PostgreSQL workload username");
        }
        return value;
    }

    private static String requireApplicationName(String value) {
        Objects.requireNonNull(value, "applicationName");
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{2,63}")) {
            throw new IllegalArgumentException("invalid PostgreSQL application name");
        }
        return value;
    }

    private static Path mountedPath(Path path, String label) {
        Objects.requireNonNull(path, label);
        Path normalized = path.normalize();
        if (!normalized.isAbsolute() || normalized.getFileName() == null
                || normalized.getParent() == null || ".".equals(normalized.getFileName().toString())
                || "..".equals(normalized.getFileName().toString())) {
            throw new IllegalArgumentException(label + " must be an absolute mounted file path");
        }
        return normalized;
    }

    private static VerifiedMount verifyMount(Path configured, MountedKind kind)
            throws SQLException {
        try {
            Path parent = configured.getParent();
            if (Files.isSymbolicLink(parent)
                    || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
                throw new SQLException("mounted secret parent is not a real directory");
            }
            // Resolve ancestor symlinks (for example macOS /var -> /private/var) before
            // comparing the pinned file.  The direct mount parent itself remains forbidden from
            // being a symlink, while projected secret files may safely resolve through ..data.
            Path parentReal = parent.toRealPath();
            if (Files.isSymbolicLink(configured)) {
                Path link = Files.readSymbolicLink(configured);
                if (link.isAbsolute() || !parent.resolve(link).normalize().startsWith(parent)) {
                    throw new SQLException("mounted secret symlink escapes its mount parent");
                }
            }
            Path real = configured.toRealPath();
            if (!real.startsWith(parentReal)
                    || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)) {
                throw new SQLException("mounted secret target escapes its mount parent");
            }
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(real,
                    LinkOption.NOFOLLOW_LINKS);
            if (permissions.stream().anyMatch(WRITE_PERMISSIONS::contains)) {
                throw new SQLException("mounted secret target must be read-only");
            }
            long size = Files.size(real);
            if (size < kind.minimumBytes || size > kind.maximumBytes) {
                throw new SQLException("mounted secret target has an invalid size");
            }
            byte[] bytes = Files.readAllBytes(real);
            if (bytes.length != size) {
                Arrays.fill(bytes, (byte) 0);
                throw new SQLException("mounted secret changed while it was being read");
            }
            return new VerifiedMount(real, bytes);
        } catch (UnsupportedOperationException failure) {
            throw new SQLException("mounted secret filesystem cannot prove read-only mode", failure);
        } catch (IOException failure) {
            throw new SQLException("mounted secret cannot be verified", failure);
        }
    }

    private static String password(byte[] bytes) throws SQLException {
        String value = strictUtf8(bytes, "database password");
        if (value.endsWith("\r\n")) {
            value = value.substring(0, value.length() - 2);
        } else if (value.endsWith("\n")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isBlank() || value.chars().anyMatch(character -> character == 0
                || character == '\r' || character == '\n')) {
            throw new SQLException("database password mount has an invalid value");
        }
        return value;
    }

    private static void validatePem(VerifiedMount mount, String label, String description)
            throws SQLException {
        byte[] bytes = mount.bytes();
        if (!asciiPem(bytes)
                || !contains(bytes, ("-----BEGIN " + label + "-----").getBytes(
                        StandardCharsets.US_ASCII))
                || !contains(bytes, ("-----END " + label + "-----").getBytes(
                        StandardCharsets.US_ASCII))) {
            throw new SQLException(description + " mount is not a bounded PEM document");
        }
    }

    private static void validatePrivateKey(VerifiedMount mount) throws SQLException {
        byte[] bytes = mount.bytes();
        boolean pkcs8 = contains(bytes, ascii("-----BEGIN PRIVATE KEY-----"))
                && contains(bytes, ascii("-----END PRIVATE KEY-----"));
        boolean encryptedPkcs8 = contains(bytes, ascii("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
                && contains(bytes, ascii("-----END ENCRYPTED PRIVATE KEY-----"));
        if (!asciiPem(bytes) || (!pkcs8 && !encryptedPkcs8)) {
            throw new SQLException(
                    "database client private key mount must be PKCS#8 PEM");
        }
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static boolean asciiPem(byte[] bytes) {
        for (byte value : bytes) {
            int character = Byte.toUnsignedInt(value);
            if (character != '\r' && character != '\n' && character != '\t'
                    && (character < 0x20 || character > 0x7e)) {
                return false;
            }
        }
        return true;
    }

    private static boolean contains(byte[] value, byte[] marker) {
        outer: for (int index = 0; index <= value.length - marker.length; index++) {
            for (int offset = 0; offset < marker.length; offset++) {
                if (value[index + offset] != marker[offset]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static void wipe(VerifiedMount mount) {
        if (mount != null) {
            Arrays.fill(mount.bytes(), (byte) 0);
        }
    }

    private static String strictUtf8(byte[] bytes, String label) throws SQLException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException failure) {
            throw new SQLException(label + " mount is not UTF-8", failure);
        }
    }
}
