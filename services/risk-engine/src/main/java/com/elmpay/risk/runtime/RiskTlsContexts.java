package com.elmpay.risk.runtime;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/** File-backed, read-only TLS 1.3 material for the risk workload and its callers. */
public final class RiskTlsContexts {
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final int MAX_CERT_BYTES = 256 * 1024;
    private static final int MAX_KEY_BYTES = 64 * 1024;
    private static final byte[] PRIVATE_KEY_BEGIN =
            "-----BEGIN PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRIVATE_KEY_END =
            "-----END PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);

    private RiskTlsContexts() { }

    public record ServerIdentity(SSLContext context) {
        public ServerIdentity {
            Objects.requireNonNull(context, "context");
        }

        public void configure(HttpsServer server) {
            Objects.requireNonNull(server, "server");
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
    }

    public static ServerIdentity server(Map<String, String> environment, Clock clock) {
        String name = required(environment, "ELMPAY_RISK_TLS_SERVER_NAME")
                .toLowerCase(Locale.ROOT);
        if (!validDnsName(name)) {
            throw new IllegalStateException("ELMPAY_RISK_TLS_SERVER_NAME is invalid");
        }
        Material material = identity(environment,
                "ELMPAY_RISK_TLS_SERVER_CERTIFICATE_FILE",
                "ELMPAY_RISK_TLS_SERVER_PRIVATE_KEY_FILE",
                "ELMPAY_RISK_TLS_CLIENT_CA_BUNDLE_FILE", SERVER_AUTH, clock);
        try {
            if (!dnsNames(material.chain().getFirst()).contains(name)) {
                throw new IllegalStateException(
                        "risk server certificate SAN does not match configured name");
            }
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("risk server certificate SAN cannot be read", failure);
        }
        return new ServerIdentity(context(material, "risk-server"));
    }

    /** Load a client identity from a prefix such as ELMPAY_RISK_SIGNAL_. */
    public static SSLContext client(Map<String, String> environment, String prefix, Clock clock) {
        if (prefix == null || !prefix.matches("[A-Z][A-Z0-9_]*_")) {
            throw new IllegalArgumentException("TLS environment prefix is invalid");
        }
        Material material = identity(environment, prefix + "CLIENT_CERTIFICATE_FILE",
                prefix + "CLIENT_PRIVATE_KEY_FILE", prefix + "CA_BUNDLE_FILE", CLIENT_AUTH,
                clock);
        return context(material, "risk-client");
    }

    private static Material identity(Map<String, String> environment, String certificateKey,
            String privateKeyKey, String trustKey, String requiredEku, Clock clock) {
        byte[] encodedCertificate = null;
        byte[] encodedPrivateKey = null;
        byte[] encodedTrust = null;
        try {
            encodedCertificate = readMounted(environment, certificateKey, MAX_CERT_BYTES);
            encodedTrust = readMounted(environment, trustKey, MAX_CERT_BYTES);
            List<X509Certificate> chain = certificates(encodedCertificate);
            List<X509Certificate> authorities = certificates(encodedTrust);
            encodedPrivateKey = readMounted(environment, privateKeyKey, MAX_KEY_BYTES);
            PrivateKey key = privateKey(encodedPrivateKey,
                    chain.getFirst().getPublicKey().getAlgorithm());
            validateChain(chain, requiredEku, clock);
            validateAuthorities(authorities, clock);
            validateKeyMatch(chain.getFirst(), key);
            return new Material(chain, key, authorities);
        } catch (IOException | GeneralSecurityException failure) {
            throw new IllegalStateException("risk mTLS material is invalid", failure);
        } finally {
            if (encodedCertificate != null) java.util.Arrays.fill(encodedCertificate, (byte) 0);
            if (encodedPrivateKey != null) java.util.Arrays.fill(encodedPrivateKey, (byte) 0);
            if (encodedTrust != null) java.util.Arrays.fill(encodedTrust, (byte) 0);
        }
    }

    private static SSLContext context(Material material, String alias) {
        char[] password = java.util.UUID.randomUUID().toString().toCharArray();
        try {
            KeyStore identity = KeyStore.getInstance("PKCS12");
            identity.load(null, password);
            identity.setKeyEntry(alias, material.privateKey(), password,
                    material.chain().toArray(Certificate[]::new));
            KeyManagerFactory keys = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keys.init(identity, password);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            for (int index = 0; index < material.authorities().size(); index++) {
                trust.setCertificateEntry("ca-" + index, material.authorities().get(index));
            }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            managers.init(trust);
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keys.getKeyManagers(), managers.getTrustManagers(), new SecureRandom());
            return context;
        } catch (IOException | GeneralSecurityException failure) {
            throw new IllegalStateException("risk TLS context cannot be initialized", failure);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    static byte[] readMounted(Map<String, String> environment, String key, int maximum)
            throws IOException {
        return RiskMountedFiles.read(environment, key, maximum);
    }

    private static List<X509Certificate> certificates(byte[] encoded)
            throws GeneralSecurityException {
        Collection<? extends Certificate> values = CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(encoded));
        if (values.isEmpty() || values.size() > 16) {
            throw new GeneralSecurityException("certificate bundle is empty or too large");
        }
        List<X509Certificate> result = new ArrayList<>();
        for (Certificate value : values) {
            if (!(value instanceof X509Certificate certificate)) {
                throw new GeneralSecurityException("non-X509 certificate in bundle");
            }
            result.add(certificate);
        }
        return List.copyOf(result);
    }

    private static PrivateKey privateKey(byte[] raw, String algorithm)
            throws GeneralSecurityException {
        if (!Set.of("RSA", "EC").contains(algorithm)) {
            throw new GeneralSecurityException("private key must be one RSA/EC PKCS#8 PEM value");
        }
        int start = skipLineWhitespace(raw, 0);
        if (!matches(raw, start, PRIVATE_KEY_BEGIN)) {
            throw new GeneralSecurityException("private key must be one RSA/EC PKCS#8 PEM value");
        }
        int bodyStart = start + PRIVATE_KEY_BEGIN.length;
        int footer = find(raw, PRIVATE_KEY_END, bodyStart);
        if (footer < bodyStart || find(raw, PRIVATE_KEY_BEGIN, bodyStart) >= 0
                || find(raw, PRIVATE_KEY_END, footer + PRIVATE_KEY_END.length) >= 0
                || skipLineWhitespace(raw, footer + PRIVATE_KEY_END.length) != raw.length) {
            throw new GeneralSecurityException("private key must be one RSA/EC PKCS#8 PEM value");
        }
        int encodedLength = 0;
        for (int index = bodyStart; index < footer; index++) {
            byte value = raw[index];
            if (value == '\r' || value == '\n') continue;
            if (!base64(value)) {
                throw new GeneralSecurityException("private key PEM is invalid");
            }
            encodedLength++;
        }
        if (encodedLength < 4 || encodedLength > MAX_KEY_BYTES || encodedLength % 4 != 0) {
            throw new GeneralSecurityException("private key PEM is invalid");
        }
        byte[] normalized = new byte[encodedLength];
        byte[] der = null;
        try {
            int target = 0;
            for (int index = bodyStart; index < footer; index++) {
                byte value = raw[index];
                if (value != '\r' && value != '\n') normalized[target++] = value;
            }
            der = Base64.getDecoder().decode(normalized);
            PKCS8EncodedKeySpec specification = new PKCS8EncodedKeySpec(der);
            PrivateKey key = KeyFactory.getInstance(algorithm).generatePrivate(specification);
            byte[] canonical = key.getEncoded();
            try {
                if (canonical == null
                        || !java.security.MessageDigest.isEqual(der, canonical)) {
                    throw new GeneralSecurityException(
                            "private key PKCS#8 encoding is not canonical");
                }
            } finally {
                if (canonical != null) java.util.Arrays.fill(canonical, (byte) 0);
            }
            return key;
        } catch (IllegalArgumentException invalid) {
            throw new GeneralSecurityException("private key PEM is invalid", invalid);
        } finally {
            java.util.Arrays.fill(normalized, (byte) 0);
            if (der != null) java.util.Arrays.fill(der, (byte) 0);
        }
    }

    private static int skipLineWhitespace(byte[] value, int start) {
        int index = start;
        while (index < value.length && (value[index] == '\r' || value[index] == '\n')) index++;
        return index;
    }

    private static boolean matches(byte[] value, int offset, byte[] expected) {
        if (offset < 0 || value.length - offset < expected.length) return false;
        for (int index = 0; index < expected.length; index++) {
            if (value[offset + index] != expected[index]) return false;
        }
        return true;
    }

    private static int find(byte[] value, byte[] expected, int start) {
        for (int index = Math.max(0, start); index <= value.length - expected.length; index++) {
            if (matches(value, index, expected)) return index;
        }
        return -1;
    }

    private static boolean base64(byte value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
                || value >= '0' && value <= '9' || value == '+' || value == '/'
                || value == '=';
    }

    static void validateChain(List<X509Certificate> chain, String eku, Clock clock)
            throws GeneralSecurityException {
        Date now = Date.from(clock.instant());
        for (X509Certificate certificate : chain) certificate.checkValidity(now);
        X509Certificate leaf = chain.getFirst();
        if (leaf.getBasicConstraints() >= 0 || leaf.getExtendedKeyUsage() == null
                || !leaf.getExtendedKeyUsage().contains(eku)) {
            throw new GeneralSecurityException("workload certificate purpose is invalid");
        }
        boolean[] leafUsage = leaf.getKeyUsage();
        if (leafUsage == null || leafUsage.length == 0 || !leafUsage[0]) {
            throw new GeneralSecurityException(
                    "workload certificate cannot sign TLS handshakes");
        }
        for (int index = 0; index + 1 < chain.size(); index++) {
            X509Certificate current = chain.get(index);
            X509Certificate issuer = chain.get(index + 1);
            requireCertificateAuthority(issuer);
            if (!current.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new GeneralSecurityException("certificate chain is out of order");
            }
            current.verify(issuer.getPublicKey());
        }
    }

    static void validateAuthorities(List<X509Certificate> authorities, Clock clock)
            throws GeneralSecurityException {
        Date now = Date.from(clock.instant());
        for (X509Certificate authority : authorities) {
            authority.checkValidity(now);
            requireCertificateAuthority(authority);
        }
    }

    private static void requireCertificateAuthority(X509Certificate certificate)
            throws GeneralSecurityException {
        boolean[] usage = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || usage == null || usage.length <= 5
                || !usage[5]) {
            throw new GeneralSecurityException(
                    "certificate authority lacks basic constraints or keyCertSign usage");
        }
    }

    private static void validateKeyMatch(X509Certificate certificate, PrivateKey key)
            throws GeneralSecurityException {
        String algorithm = switch (certificate.getPublicKey().getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new GeneralSecurityException("unsupported certificate key algorithm");
        };
        byte[] challenge = "elmpay-risk-tls-key-match-v1".getBytes(StandardCharsets.US_ASCII);
        byte[] signed = null;
        try {
            Signature signer = Signature.getInstance(algorithm);
            signer.initSign(key);
            signer.update(challenge);
            signed = signer.sign();
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            if (!verifier.verify(signed)) {
                throw new GeneralSecurityException("certificate and private key do not match");
            }
        } finally {
            java.util.Arrays.fill(challenge, (byte) 0);
            if (signed != null) java.util.Arrays.fill(signed, (byte) 0);
        }
    }

    private static Set<String> dnsNames(X509Certificate certificate)
            throws GeneralSecurityException {
        Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        if (names == null) return Set.of();
        Set<String> result = new HashSet<>();
        for (List<?> entry : names) {
            if (entry.size() == 2 && Integer.valueOf(2).equals(entry.getFirst())
                    && entry.get(1) instanceof String name && !name.contains("*")) {
                result.add(name.toLowerCase(Locale.ROOT));
            }
        }
        return Set.copyOf(result);
    }

    private static boolean validDnsName(String value) {
        return value != null && value.length() <= 253
                && value.matches("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+"
                + "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) throw new IllegalStateException(key + " is required");
        return value;
    }

    private record Material(List<X509Certificate> chain, PrivateKey privateKey,
            List<X509Certificate> authorities) { }
}
