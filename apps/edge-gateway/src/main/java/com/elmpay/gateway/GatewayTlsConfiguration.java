package com.elmpay.gateway;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/** Loads a bounded, read-only TLS identity and enforces mutual TLS 1.3. */
public final class GatewayTlsConfiguration {
    private static final int MAX_CERTIFICATE_BYTES = 256 * 1024;
    private static final int MAX_PRIVATE_KEY_BYTES = 64 * 1024;
    private static final String SERVER_AUTH_EKU = "1.3.6.1.5.5.7.3.1";

    private final SSLContext context;

    private GatewayTlsConfiguration(SSLContext context) {
        this.context = context;
    }

    public static GatewayTlsConfiguration fromEnvironment(Map<String, String> environment,
            Clock clock) {
        try {
            Path certificateFile = Path.of(required(environment,
                    "ELMPAY_TLS_SERVER_CERTIFICATE_FILE"));
            Path privateKeyFile = Path.of(required(environment,
                    "ELMPAY_TLS_SERVER_PRIVATE_KEY_FILE"));
            Path trustBundleFile = Path.of(required(environment,
                    "ELMPAY_TLS_CLIENT_CA_BUNDLE_FILE"));
            String serverName = required(environment, "ELMPAY_TLS_SERVER_NAME")
                    .toLowerCase(Locale.ROOT);
            if (!serverName.matches("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+"
                    + "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
                throw new IllegalStateException("ELMPAY_TLS_SERVER_NAME is invalid");
            }
            List<X509Certificate> serverChain = certificates(readMounted(certificateFile,
                    MAX_CERTIFICATE_BYTES, false, "server certificate"));
            List<X509Certificate> clientAuthorities = certificates(readMounted(trustBundleFile,
                    MAX_CERTIFICATE_BYTES, false, "client CA bundle"));
            PrivateKey privateKey = privateKey(readMounted(privateKeyFile,
                    MAX_PRIVATE_KEY_BYTES, true, "server private key"),
                    serverChain.getFirst().getPublicKey().getAlgorithm());
            validateServerChain(serverChain, serverName, clock);
            validateAuthorities(clientAuthorities, clock);
            validateKeyMatch(serverChain.getFirst(), privateKey);
            return new GatewayTlsConfiguration(context(serverChain, privateKey, clientAuthorities));
        } catch (IOException | GeneralSecurityException failure) {
            throw new IllegalStateException("gateway mTLS configuration is invalid", failure);
        }
    }

    public void configure(HttpsServer server) {
        server.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters parameters) {
                SSLParameters policy = context.getDefaultSSLParameters();
                policy.setProtocols(new String[] {"TLSv1.3"});
                policy.setNeedClientAuth(true);
                parameters.setSSLParameters(policy);
            }
        });
    }

    private static SSLContext context(List<X509Certificate> chain, PrivateKey privateKey,
            List<X509Certificate> authorities) throws GeneralSecurityException, IOException {
        char[] password = java.util.UUID.randomUUID().toString().toCharArray();
        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, password);
        identity.setKeyEntry("edge-gateway", privateKey, password,
                chain.toArray(Certificate[]::new));
        KeyManagerFactory keys = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keys.init(identity, password);

        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        for (int index = 0; index < authorities.size(); index++) {
            trust.setCertificateEntry("client-ca-" + index, authorities.get(index));
        }
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), trustManagers.getTrustManagers(), new SecureRandom());
        java.util.Arrays.fill(password, '\0');
        return context;
    }

    private static byte[] readMounted(Path configured, int maximumBytes, boolean privateFile,
            String name) throws IOException {
        if (!configured.isAbsolute()) {
            throw new IllegalStateException(name + " path must be absolute");
        }
        Path mount = configured.getParent().toRealPath();
        Path path = configured.toRealPath();
        if (!path.startsWith(mount) || !Files.isRegularFile(path)) {
            throw new IllegalStateException(name + " must remain inside its mounted directory");
        }
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            if (permissions.contains(PosixFilePermission.OWNER_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || (privateFile && permissions.contains(PosixFilePermission.OTHERS_READ))) {
                throw new IllegalStateException(name + " mount permissions are too broad");
            }
        } catch (UnsupportedOperationException unsupported) {
            if (Files.isWritable(path)) {
                throw new IllegalStateException(name + " mount must be read-only", unsupported);
            }
        }
        try (var input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(maximumBytes + 1);
            if (bytes.length == 0 || bytes.length > maximumBytes) {
                throw new IllegalStateException(name + " is empty or too large");
            }
            return bytes;
        }
    }

    private static List<X509Certificate> certificates(byte[] bytes)
            throws GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> parsed = factory.generateCertificates(
                new ByteArrayInputStream(bytes));
        if (parsed.isEmpty() || parsed.size() > 16) {
            throw new GeneralSecurityException("certificate bundle is empty or too large");
        }
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate certificate : parsed) {
            if (!(certificate instanceof X509Certificate x509)) {
                throw new GeneralSecurityException("certificate bundle contains a non-X509 value");
            }
            result.add(x509);
        }
        return List.copyOf(result);
    }

    private static PrivateKey privateKey(byte[] bytes, String algorithm)
            throws GeneralSecurityException {
        String value = new String(bytes, StandardCharsets.US_ASCII).strip();
        String begin = "-----BEGIN PRIVATE KEY-----";
        String end = "-----END PRIVATE KEY-----";
        if (!value.startsWith(begin) || !value.endsWith(end)
                || value.indexOf(begin, begin.length()) >= 0) {
            throw new GeneralSecurityException("server key must be one unencrypted PKCS#8 key");
        }
        String encoded = value.substring(begin.length(), value.length() - end.length())
                .replace("\r", "").replace("\n", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException invalid) {
            throw new GeneralSecurityException("server private key PEM is invalid", invalid);
        }
        if (!Set.of("RSA", "EC").contains(algorithm)) {
            throw new GeneralSecurityException("server certificate key algorithm is unsupported");
        }
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    static void validateServerChain(List<X509Certificate> chain, String serverName,
            Clock clock) throws GeneralSecurityException {
        Date now = Date.from(clock.instant());
        for (X509Certificate certificate : chain) {
            certificate.checkValidity(now);
        }
        X509Certificate leaf = chain.getFirst();
        if (leaf.getBasicConstraints() >= 0 || leaf.getExtendedKeyUsage() == null
                || !leaf.getExtendedKeyUsage().contains(SERVER_AUTH_EKU)) {
            throw new GeneralSecurityException("server certificate purpose is invalid");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
            throw new GeneralSecurityException("server certificate cannot sign TLS handshakes");
        }
        if (!dnsNames(leaf).contains(serverName)) {
            throw new GeneralSecurityException("server certificate SAN does not match server name");
        }
        for (int index = 0; index + 1 < chain.size(); index++) {
            X509Certificate certificate = chain.get(index);
            X509Certificate issuer = chain.get(index + 1);
            if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new GeneralSecurityException("server certificate chain is out of order");
            }
            certificate.verify(issuer.getPublicKey());
        }
    }

    private static Set<String> dnsNames(X509Certificate certificate)
            throws GeneralSecurityException {
        Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        if (names == null) {
            return Set.of();
        }
        java.util.HashSet<String> result = new java.util.HashSet<>();
        for (List<?> entry : names) {
            if (entry.size() == 2 && Integer.valueOf(2).equals(entry.getFirst())
                    && entry.get(1) instanceof String dns && !dns.contains("*")) {
                result.add(dns.toLowerCase(Locale.ROOT));
            }
        }
        return Set.copyOf(result);
    }

    static void validateAuthorities(List<X509Certificate> authorities, Clock clock)
            throws GeneralSecurityException {
        Date now = Date.from(clock.instant());
        for (X509Certificate authority : authorities) {
            authority.checkValidity(now);
            boolean[] usage = authority.getKeyUsage();
            if (authority.getBasicConstraints() < 0
                    || (usage != null && (usage.length <= 5 || !usage[5]))) {
                throw new GeneralSecurityException("client trust bundle contains a non-CA certificate");
            }
        }
    }

    static void validateKeyMatch(X509Certificate certificate, PrivateKey key)
            throws GeneralSecurityException {
        String signatureAlgorithm = switch (certificate.getPublicKey().getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new GeneralSecurityException("server key algorithm is unsupported");
        };
        byte[] challenge = "elmpay-edge-tls-key-match-v1".getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(key);
        signer.update(challenge);
        byte[] signed = signer.sign();
        Signature verifier = Signature.getInstance(signatureAlgorithm);
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(challenge);
        if (!verifier.verify(signed)) {
            throw new GeneralSecurityException("server certificate and private key do not match");
        }
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }
}
