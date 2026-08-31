package com.elmpay.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/**
 * Production HTTPS client material loaded from one exact projected-secret mount.
 *
 * <p>The four configured paths are not caller-selectable filesystem paths: they must match the
 * exact certificate, private-key, trust-bundle and token locations under the supplied workload
 * mount. Kubernetes projected-secret rotation is supported because every token read resolves the
 * path again. Certificate and private-key material is validated once during startup, so incomplete
 * or unsafe mounts fail closed before a runtime begins serving work.
 *
 * <p>Private-key PEM and transient token bytes owned by this class are wiped. The JDK HTTP header
 * API requires an immutable access-token {@link String}; that String, provider-owned
 * {@link PrivateKey}/{@link KeyStore}/{@link SSLContext} state and JDK-owned TLS/socket buffers are
 * outside the synchronous erasure boundary and must never be logged.
 */
public final class MountedHttpsClient {
    private static final Path SECRET_ROOT = Path.of("/var/run/secrets/elmpay");
    private static final int MAX_CERTIFICATE_BYTES = 1024 * 1024;
    private static final int MAX_PRIVATE_KEY_BYTES = 64 * 1024;
    private static final int MAX_TOKEN_BYTES = 8 * 1024;
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final byte[] PRIVATE_KEY_BEGIN =
            "-----BEGIN PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRIVATE_KEY_END =
            "-----END PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);
    private static final Set<PosixFilePermission> WRITE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_WRITE);

    private MountedHttpsClient() {
    }

    /** An exact TLS 1.3 client plus a rotating mounted bearer-token reader. */
    public record Client(HttpClient httpClient, Supplier<String> accessToken) {
        public Client {
            Objects.requireNonNull(httpClient, "httpClient");
            Objects.requireNonNull(accessToken, "accessToken");
            BoundedHttpTransport.requireHttpsClient(httpClient);
        }
    }

    /**
     * Loads one production client from {@code /var/run/secrets/elmpay/<mountDirectory>}.
     *
     * <p>Environment names are {@code <prefix>_MTLS_CLIENT_CERT_FILE},
     * {@code <prefix>_MTLS_CLIENT_KEY_FILE}, {@code <prefix>_MTLS_TRUST_BUNDLE_FILE} and
     * {@code <prefix>_ACCESS_TOKEN_FILE}. A legacy boolean {@code <prefix>_MTLS} is rejected.
     */
    public static Client fromEnvironment(Map<String, String> environment, String prefix,
            String mountDirectory, Clock clock, Duration connectTimeout) {
        Objects.requireNonNull(environment, "environment");
        requirePrefix(prefix);
        if (mountDirectory == null
                || !mountDirectory.matches("[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")) {
            throw new IllegalArgumentException("HTTPS secret mount directory is invalid");
        }
        if (environment.containsKey(prefix + "_MTLS")) {
            throw new IllegalStateException(
                    prefix + "_MTLS is unsupported; exact mounted material is required");
        }
        Path mount = SECRET_ROOT.resolve(mountDirectory).normalize();
        MountedFile certificate = required(environment, prefix + "_MTLS_CLIENT_CERT_FILE",
                mount, "tls.crt", MAX_CERTIFICATE_BYTES);
        MountedFile privateKey = required(environment, prefix + "_MTLS_CLIENT_KEY_FILE",
                mount, "tls.key", MAX_PRIVATE_KEY_BYTES);
        MountedFile trustBundle = required(environment, prefix + "_MTLS_TRUST_BUNDLE_FILE",
                mount, "ca.crt", MAX_CERTIFICATE_BYTES);
        MountedFile token = required(environment, prefix + "_ACCESS_TOKEN_FILE",
                mount, "token", MAX_TOKEN_BYTES);
        return load(certificate, privateKey, trustBundle, token, clock, connectTimeout);
    }

    /**
     * Loads only an exact mounted mTLS identity and trust bundle for a client whose application
     * authentication is supplied by another short-lived credential boundary.
     */
    public static SSLContext mutualTlsContextFromEnvironment(Map<String, String> environment,
            String prefix, String mountDirectory, Clock clock) {
        Objects.requireNonNull(environment, "environment");
        requirePrefix(prefix);
        if (mountDirectory == null
                || !mountDirectory.matches("[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")) {
            throw new IllegalArgumentException("HTTPS secret mount directory is invalid");
        }
        if (environment.containsKey(prefix + "_MTLS")) {
            throw new IllegalStateException(
                    prefix + "_MTLS is unsupported; exact mounted material is required");
        }
        Path mount = SECRET_ROOT.resolve(mountDirectory).normalize();
        MountedFile certificate = required(environment, prefix + "_MTLS_CLIENT_CERT_FILE",
                mount, "tls.crt", MAX_CERTIFICATE_BYTES);
        MountedFile privateKey = required(environment, prefix + "_MTLS_CLIENT_KEY_FILE",
                mount, "tls.key", MAX_PRIVATE_KEY_BYTES);
        MountedFile trustBundle = required(environment, prefix + "_MTLS_TRUST_BUNDLE_FILE",
                mount, "ca.crt", MAX_CERTIFICATE_BYTES);
        return context(certificate, privateKey, trustBundle, Objects.requireNonNull(clock, "clock"));
    }

    /** Reads an additional exact, bounded file from a production projected-secret mount. */
    public static byte[] readExactMountedFile(Map<String, String> environment,
            String environmentKey, String mountDirectory, String filename, int maximumBytes) {
        Objects.requireNonNull(environment, "environment");
        if (environmentKey == null || !environmentKey.matches("ELMPAY_[A-Z0-9_]+_FILE")
                || mountDirectory == null
                || !mountDirectory.matches("[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
                || filename == null
                || !filename.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
                || maximumBytes < 1 || maximumBytes > MAX_CERTIFICATE_BYTES) {
            throw new IllegalArgumentException("additional HTTPS mount binding is invalid");
        }
        Path mount = SECRET_ROOT.resolve(mountDirectory).normalize();
        try {
            return read(required(environment, environmentKey, mount, filename, maximumBytes));
        } catch (IOException failure) {
            throw new IllegalStateException(environmentKey + " cannot be read safely", failure);
        }
    }

    static Client loadForTest(Path certificate, Path privateKey, Path trustBundle, Path token,
            Clock clock, Duration connectTimeout) {
        Path common = commonParent(certificate, privateKey, trustBundle, token);
        return load(new MountedFile(certificate.toAbsolutePath().normalize(), common, "tls.crt",
                        MAX_CERTIFICATE_BYTES),
                new MountedFile(privateKey.toAbsolutePath().normalize(), common, "tls.key",
                        MAX_PRIVATE_KEY_BYTES),
                new MountedFile(trustBundle.toAbsolutePath().normalize(), common, "ca.crt",
                        MAX_CERTIFICATE_BYTES),
                new MountedFile(token.toAbsolutePath().normalize(), common, "token",
                        MAX_TOKEN_BYTES), clock, connectTimeout);
    }

    static String readTokenForTest(Path token) {
        Path absolute = Objects.requireNonNull(token, "token").toAbsolutePath().normalize();
        return readToken(new MountedFile(absolute,
                Objects.requireNonNull(absolute.getParent(), "token parent"),
                absolute.getFileName().toString(), MAX_TOKEN_BYTES));
    }

    private static Client load(MountedFile certificate, MountedFile privateKey,
            MountedFile trustBundle, MountedFile token, Clock clock, Duration connectTimeout) {
        Objects.requireNonNull(clock, "clock");
        Duration timeout = positiveBounded(connectTimeout);
        SSLContext context = context(certificate, privateKey, trustBundle, clock);

        // Validate the token mount and its format during startup without manufacturing an
        // immutable secret String that would survive until GC. Later requests resolve the
        // projected path again, allowing an atomic Kubernetes secret rotation.
        validateToken(token);
        Supplier<String> rotatingToken = () -> readToken(token);
        SSLParameters parameters = new SSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        HttpClient client = HttpClient.newBuilder().sslContext(context).sslParameters(parameters)
                .connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).build();
        return new Client(client, rotatingToken);
    }

    private static SSLContext context(MountedFile certificateFile, MountedFile privateKeyFile,
            MountedFile trustBundleFile, Clock clock) {
        byte[] encodedCertificate = null;
        byte[] encodedPrivateKey = null;
        byte[] encodedTrust = null;
        char[] password = null;
        try {
            encodedCertificate = read(certificateFile);
            encodedPrivateKey = read(privateKeyFile);
            encodedTrust = read(trustBundleFile);
            List<X509Certificate> chain = certificates(encodedCertificate, "client certificate");
            List<X509Certificate> authorities = certificates(encodedTrust, "trust bundle");
            validateClientChain(chain, clock);
            validateAuthorities(authorities, clock);
            PrivateKey privateKey = privateKey(encodedPrivateKey,
                    chain.getFirst().getPublicKey().getAlgorithm());
            validateKeyMatch(chain.getFirst(), privateKey);

            password = java.util.UUID.randomUUID().toString().toCharArray();
            KeyStore identity = KeyStore.getInstance("PKCS12");
            identity.load(null, password);
            identity.setKeyEntry("elmpay-client", privateKey, password,
                    chain.toArray(Certificate[]::new));
            KeyManagerFactory keys = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keys.init(identity, password);

            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            for (int index = 0; index < authorities.size(); index++) {
                trust.setCertificateEntry("authority-" + index, authorities.get(index));
            }
            TrustManagerFactory trusts = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trusts.init(trust);
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keys.getKeyManagers(), trusts.getTrustManagers(), new SecureRandom());
            return context;
        } catch (IOException | GeneralSecurityException failure) {
            throw new IllegalStateException("mounted HTTPS mTLS material is invalid", failure);
        } finally {
            wipe(encodedCertificate);
            wipe(encodedPrivateKey);
            wipe(encodedTrust);
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private static List<X509Certificate> certificates(byte[] encoded, String kind)
            throws GeneralSecurityException {
        Collection<? extends Certificate> parsed = CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(encoded));
        if (parsed.isEmpty() || parsed.size() > 16) {
            throw new GeneralSecurityException(kind + " is empty or too large");
        }
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate value : parsed) {
            if (!(value instanceof X509Certificate certificate)) {
                throw new GeneralSecurityException(kind + " contains a non-X.509 certificate");
            }
            result.add(certificate);
        }
        return List.copyOf(result);
    }

    private static void validateClientChain(List<X509Certificate> chain, Clock clock)
            throws GeneralSecurityException {
        Date now = Date.from(clock.instant());
        Set<String> digests = new HashSet<>();
        for (X509Certificate certificate : chain) {
            certificate.checkValidity(now);
            if (!digests.add(certificateDigest(certificate))) {
                throw new GeneralSecurityException("client certificate chain contains a duplicate");
            }
        }
        X509Certificate leaf = chain.getFirst();
        List<String> extended = leaf.getExtendedKeyUsage();
        boolean[] usage = leaf.getKeyUsage();
        if (leaf.getBasicConstraints() >= 0 || extended == null || !extended.contains(CLIENT_AUTH)
                || usage == null || usage.length == 0 || !usage[0]) {
            throw new GeneralSecurityException(
                    "client certificate must be a digitalSignature clientAuth leaf");
        }
        for (int index = 0; index + 1 < chain.size(); index++) {
            X509Certificate current = chain.get(index);
            X509Certificate issuer = chain.get(index + 1);
            requireCertificateAuthority(issuer);
            if (!current.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new GeneralSecurityException("client certificate chain is out of order");
            }
            current.verify(issuer.getPublicKey());
        }
    }

    private static void validateAuthorities(List<X509Certificate> authorities, Clock clock)
            throws GeneralSecurityException {
        Date now = Date.from(clock.instant());
        Set<String> digests = new HashSet<>();
        for (X509Certificate authority : authorities) {
            authority.checkValidity(now);
            requireCertificateAuthority(authority);
            if (!digests.add(certificateDigest(authority))) {
                throw new GeneralSecurityException("trust bundle contains a duplicate certificate");
            }
        }
    }

    private static void requireCertificateAuthority(X509Certificate certificate)
            throws GeneralSecurityException {
        boolean[] usage = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || usage == null || usage.length <= 5
                || !usage[5]) {
            throw new GeneralSecurityException(
                    "trust certificate lacks CA basic constraints or keyCertSign usage");
        }
    }

    private static String certificateDigest(X509Certificate certificate)
            throws GeneralSecurityException {
        byte[] encoded = certificate.getEncoded();
        byte[] digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            return java.util.HexFormat.of().formatHex(digest);
        } finally {
            Arrays.fill(encoded, (byte) 0);
            wipe(digest);
        }
    }

    private static PrivateKey privateKey(byte[] raw, String publicAlgorithm)
            throws GeneralSecurityException {
        String algorithm = switch (publicAlgorithm.toUpperCase(Locale.ROOT)) {
            case "RSA" -> "RSA";
            case "EC" -> "EC";
            case "ED25519", "EDDSA" -> "Ed25519";
            default -> throw new GeneralSecurityException("unsupported mTLS private-key algorithm");
        };
        int start = skipLineWhitespace(raw, 0);
        if (!matches(raw, start, PRIVATE_KEY_BEGIN)) {
            throw new GeneralSecurityException("private key must be one PKCS#8 PEM value");
        }
        int bodyStart = start + PRIVATE_KEY_BEGIN.length;
        int footer = find(raw, PRIVATE_KEY_END, bodyStart);
        if (footer < bodyStart || find(raw, PRIVATE_KEY_BEGIN, bodyStart) >= 0
                || find(raw, PRIVATE_KEY_END, footer + PRIVATE_KEY_END.length) >= 0
                || skipLineWhitespace(raw, footer + PRIVATE_KEY_END.length) != raw.length) {
            throw new GeneralSecurityException("private key must be one PKCS#8 PEM value");
        }
        int encodedLength = 0;
        for (int index = bodyStart; index < footer; index++) {
            byte value = raw[index];
            if (value == '\r' || value == '\n') {
                continue;
            }
            if (!base64(value)) {
                throw new GeneralSecurityException("private key PEM is invalid");
            }
            encodedLength = Math.addExact(encodedLength, 1);
        }
        if (encodedLength < 4 || encodedLength > MAX_PRIVATE_KEY_BYTES
                || encodedLength % 4 != 0) {
            throw new GeneralSecurityException("private key PEM is invalid");
        }
        byte[] normalized = new byte[encodedLength];
        byte[] der = null;
        try {
            int target = 0;
            for (int index = bodyStart; index < footer; index++) {
                byte value = raw[index];
                if (value != '\r' && value != '\n') {
                    normalized[target++] = value;
                }
            }
            der = Base64.getDecoder().decode(normalized);
            PrivateKey key = KeyFactory.getInstance(algorithm)
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
            byte[] canonical = key.getEncoded();
            try {
                if (canonical == null || !MessageDigest.isEqual(der, canonical)) {
                    throw new GeneralSecurityException(
                            "private key PKCS#8 encoding is not canonical");
                }
            } finally {
                wipe(canonical);
            }
            return key;
        } catch (IllegalArgumentException failure) {
            throw new GeneralSecurityException("private key PEM is invalid", failure);
        } finally {
            Arrays.fill(normalized, (byte) 0);
            wipe(der);
        }
    }

    private static void validateKeyMatch(X509Certificate certificate, PrivateKey privateKey)
            throws GeneralSecurityException {
        String algorithm = switch (certificate.getPublicKey().getAlgorithm().toUpperCase(
                Locale.ROOT)) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "ED25519", "EDDSA" -> "Ed25519";
            default -> throw new GeneralSecurityException("unsupported mTLS public-key algorithm");
        };
        byte[] challenge = "elmpay-mounted-https-key-binding-v1"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] signed = null;
        try {
            Signature signer = Signature.getInstance(algorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            signed = signer.sign();
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            if (!verifier.verify(signed)) {
                throw new GeneralSecurityException(
                        "mTLS private key does not match the client certificate");
            }
        } finally {
            Arrays.fill(challenge, (byte) 0);
            wipe(signed);
        }
    }

    private static String readToken(MountedFile token) {
        byte[] encoded = null;
        try {
            encoded = read(token);
            int length = validateTokenBytes(encoded);
            return new String(encoded, 0, length, StandardCharsets.US_ASCII);
        } catch (IOException failure) {
            throw new IllegalStateException("mounted HTTPS access token cannot be read", failure);
        } finally {
            wipe(encoded);
        }
    }

    private static void validateToken(MountedFile token) {
        byte[] encoded = null;
        try {
            encoded = read(token);
            validateTokenBytes(encoded);
        } catch (IOException failure) {
            throw new IllegalStateException("mounted HTTPS access token cannot be read", failure);
        } finally {
            wipe(encoded);
        }
    }

    private static int validateTokenBytes(byte[] encoded) {
        int length = encoded.length;
        if (length > 0 && encoded[length - 1] == '\n') {
            length--;
            if (length > 0 && encoded[length - 1] == '\r') {
                length--;
            }
        }
        if (length < 32 || length > MAX_TOKEN_BYTES || !token68(encoded, length)) {
            throw new SecurityException("mounted HTTPS access token is malformed");
        }
        return length;
    }

    private static boolean token68(byte[] value, int length) {
        int paddingStart = length;
        while (paddingStart > 0 && value[paddingStart - 1] == '=') {
            paddingStart--;
        }
        if (paddingStart == 0) {
            return false;
        }
        for (int index = 0; index < length; index++) {
            int character = Byte.toUnsignedInt(value[index]);
            boolean core = character >= 'A' && character <= 'Z'
                    || character >= 'a' && character <= 'z'
                    || character >= '0' && character <= '9'
                    || character == '-' || character == '.' || character == '_'
                    || character == '~' || character == '+' || character == '/';
            if (index < paddingStart ? !core : character != '=') {
                return false;
            }
        }
        return true;
    }

    private static byte[] read(MountedFile mounted) throws IOException {
        Path expected = mounted.mountRoot().resolve(mounted.filename()).normalize();
        if (!expected.equals(mounted.configured())) {
            throw new IOException("mounted HTTPS file path changed after validation");
        }
        Path root = mounted.mountRoot().toRealPath();
        Path real = mounted.configured().toRealPath();
        long size = Files.size(real);
        if (!real.startsWith(root) || !Files.isRegularFile(real) || size < 1
                || size > mounted.maximumBytes()) {
            throw new IOException("mounted HTTPS file escaped its mount or exceeds its bound");
        }
        try {
            if (Files.getPosixFilePermissions(real).stream().anyMatch(
                    WRITE_PERMISSIONS::contains)) {
                throw new IOException("mounted HTTPS file must be read-only");
            }
        } catch (UnsupportedOperationException unsupported) {
            if (Files.isWritable(real)) {
                throw new IOException("mounted HTTPS file must be read-only", unsupported);
            }
        }
        try (var input = Files.newInputStream(real)) {
            byte[] value = input.readNBytes(mounted.maximumBytes() + 1);
            if (value.length < 1 || value.length > mounted.maximumBytes()) {
                wipe(value);
                throw new IOException("mounted HTTPS file has an invalid size");
            }
            return value;
        }
    }

    private static MountedFile required(Map<String, String> environment, String key,
            Path mount, String filename, int maximumBytes) {
        String raw = environment.get(key);
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        Path expected = mount.resolve(filename).normalize();
        Path configured = Path.of(raw).normalize();
        if (!configured.isAbsolute() || !configured.equals(expected)
                || !expected.startsWith(SECRET_ROOT)) {
            throw new IllegalStateException(key + " must use its exact projected-secret path");
        }
        return new MountedFile(configured, mount, filename, maximumBytes);
    }

    private static Path commonParent(Path... values) {
        Path result = null;
        for (Path value : values) {
            Path parent = Objects.requireNonNull(
                    Objects.requireNonNull(value, "mounted path").toAbsolutePath()
                            .normalize().getParent(), "mounted path parent");
            if (result == null) {
                result = parent;
            } else if (!result.equals(parent)) {
                throw new IllegalArgumentException("test HTTPS files must share one mount");
            }
        }
        return Objects.requireNonNull(result, "mounted path parent");
    }

    private static Duration positiveBounded(Duration value) {
        Objects.requireNonNull(value, "connectTimeout");
        if (value.isZero() || value.isNegative() || value.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("HTTPS connect timeout must be 1ms..10s");
        }
        return value;
    }

    private static void requirePrefix(String prefix) {
        if (prefix == null || !prefix.matches("ELMPAY_[A-Z0-9_]+")) {
            throw new IllegalArgumentException("HTTPS environment prefix is invalid");
        }
    }

    private static int skipLineWhitespace(byte[] value, int start) {
        int index = start;
        while (index < value.length && (value[index] == '\r' || value[index] == '\n')) {
            index++;
        }
        return index;
    }

    private static boolean matches(byte[] value, int offset, byte[] expected) {
        if (offset < 0 || value.length - offset < expected.length) {
            return false;
        }
        for (int index = 0; index < expected.length; index++) {
            if (value[offset + index] != expected[index]) {
                return false;
            }
        }
        return true;
    }

    private static int find(byte[] value, byte[] expected, int start) {
        for (int index = Math.max(0, start); index <= value.length - expected.length; index++) {
            if (matches(value, index, expected)) {
                return index;
            }
        }
        return -1;
    }

    private static boolean base64(byte value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
                || value >= '0' && value <= '9' || value == '+' || value == '/'
                || value == '=';
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private record MountedFile(Path configured, Path mountRoot, String filename,
            int maximumBytes) {
        private MountedFile {
            Objects.requireNonNull(configured, "configured");
            Objects.requireNonNull(mountRoot, "mountRoot");
            if (!configured.isAbsolute() || !mountRoot.isAbsolute()
                    || filename == null || !filename.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
                    || maximumBytes < 1 || maximumBytes > MAX_CERTIFICATE_BYTES) {
                throw new IllegalArgumentException("mounted HTTPS file binding is invalid");
            }
        }
    }
}
