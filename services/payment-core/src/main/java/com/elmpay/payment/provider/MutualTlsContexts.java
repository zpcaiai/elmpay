package com.elmpay.payment.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Builds a dedicated mTLS context from an exact client identity and trust bundle. */
final class MutualTlsContexts {
    private static final int MAX_PRIVATE_KEY_BYTES = 64 * 1024;
    private static final int MAX_CERTIFICATE_BUNDLE_BYTES = 1024 * 1024;
    private static final String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";
    private static final String ANY_EXTENDED_KEY_USAGE_OID = "2.5.29.37.0";
    private static final Set<PosixFilePermission> WRITE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_WRITE);

    private MutualTlsContexts() {
    }

    static SSLContext fromEnvironment(Map<String, String> environment, String prefix, Clock clock) {
        Objects.requireNonNull(environment, "environment");
        requirePrefix(prefix);
        String legacyBoolean = environment.get(prefix + "_MTLS");
        if (legacyBoolean != null && !legacyBoolean.isBlank()) {
            throw new IllegalStateException(prefix
                    + "_MTLS is unsupported; explicit certificate, key and trust paths are required");
        }
        Path certificate = configuredPath(environment, prefix + "_MTLS_CLIENT_CERT_FILE");
        Path privateKey = configuredPath(environment, prefix + "_MTLS_CLIENT_KEY_FILE");
        Path trustBundle = configuredPath(environment, prefix + "_MTLS_TRUST_BUNDLE_FILE");
        return load(certificate, privateKey, trustBundle, clock);
    }

    static boolean anyConfiguration(Map<String, String> environment, String prefix) {
        requirePrefix(prefix);
        return List.of("_MTLS", "_MTLS_CLIENT_CERT_FILE", "_MTLS_CLIENT_KEY_FILE",
                "_MTLS_TRUST_BUNDLE_FILE").stream()
                .map(prefix::concat).map(environment::get)
                .anyMatch(value -> value != null && !value.isBlank());
    }

    static SSLContext load(Path certificateFile, Path privateKeyFile, Path trustBundleFile,
            Clock clock) {
        Objects.requireNonNull(clock, "clock");
        try {
            List<X509Certificate> clientChain = certificates(certificateFile,
                    MAX_CERTIFICATE_BUNDLE_BYTES, "client certificate");
            X509Certificate leaf = clientChain.getFirst();
            validateClientCertificate(leaf, clock);
            for (X509Certificate certificate : clientChain) {
                certificate.checkValidity(Date.from(clock.instant()));
            }
            PrivateKey privateKey = privateKey(privateKeyFile, leaf);
            verifyKeyPair(privateKey, leaf.getPublicKey());
            List<X509Certificate> trust = certificates(trustBundleFile,
                    MAX_CERTIFICATE_BUNDLE_BYTES, "trust bundle");
            Set<String> trustDigests = new HashSet<>();
            for (X509Certificate certificate : trust) {
                certificate.checkValidity(Date.from(clock.instant()));
                String digest = Base64.getEncoder().encodeToString(MessageDigest.getInstance(
                        "SHA-256").digest(certificate.getEncoded()));
                if (!trustDigests.add(digest)) {
                    throw new GeneralSecurityException("trust bundle contains a duplicate certificate");
                }
            }

            char[] ephemeralPassword = java.util.UUID.randomUUID().toString().toCharArray();
            try {
                KeyStore identity = KeyStore.getInstance("PKCS12");
                identity.load(null, null);
                identity.setKeyEntry("elmpay-client", privateKey, ephemeralPassword,
                        clientChain.toArray(X509Certificate[]::new));
                KeyManagerFactory keys = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                keys.init(identity, ephemeralPassword);
                if (!hasPrivateKey(identity)) {
                    throw new GeneralSecurityException("mTLS identity contains no private key");
                }

                KeyStore anchors = KeyStore.getInstance("PKCS12");
                anchors.load(null, null);
                for (int index = 0; index < trust.size(); index++) {
                    anchors.setCertificateEntry("anchor-" + index, trust.get(index));
                }
                TrustManagerFactory trusts = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trusts.init(anchors);
                SSLContext context = SSLContext.getInstance("TLSv1.3");
                context.init(keys.getKeyManagers(), trusts.getTrustManagers(), null);
                return context;
            } finally {
                java.util.Arrays.fill(ephemeralPassword, '\0');
            }
        } catch (GeneralSecurityException | IOException exception) {
            throw new IllegalStateException("unable to load dedicated mTLS identity and trust", exception);
        }
    }

    static void verifyKeyPair(PrivateKey privateKey, java.security.PublicKey publicKey) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        if (!privateKey.getAlgorithm().equalsIgnoreCase(publicKey.getAlgorithm())) {
            throw new SecurityException("mTLS private key algorithm does not match certificate");
        }
        String signatureAlgorithm = switch (publicKey.getAlgorithm().toUpperCase(
                java.util.Locale.ROOT)) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            case "ED25519", "EDDSA" -> "Ed25519";
            default -> throw new SecurityException("unsupported mTLS client key algorithm");
        };
        byte[] challenge = "elmpay-mtls-key-binding-v1".getBytes(StandardCharsets.US_ASCII);
        try {
            Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signed = signer.sign();
            Signature verifier = Signature.getInstance(signatureAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            if (!verifier.verify(signed)) {
                throw new SecurityException("mTLS private key does not match client certificate");
            }
        } catch (GeneralSecurityException exception) {
            throw new SecurityException("mTLS private key does not match client certificate",
                    exception);
        }
    }

    private static List<X509Certificate> certificates(Path path, int maximumBytes, String kind)
            throws GeneralSecurityException, IOException {
        List<byte[]> blocks = pemBlocks(read(path, maximumBytes, kind), "CERTIFICATE", kind);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> result = new ArrayList<>();
        for (byte[] block : blocks) {
            if (!(factory.generateCertificate(new ByteArrayInputStream(block))
                    instanceof X509Certificate certificate)) {
                throw new GeneralSecurityException(kind + " is not X.509");
            }
            result.add(certificate);
        }
        return List.copyOf(result);
    }

    private static PrivateKey privateKey(Path path, X509Certificate certificate)
            throws GeneralSecurityException, IOException {
        List<byte[]> blocks = pemBlocks(read(path, MAX_PRIVATE_KEY_BYTES, "client private key"),
                "PRIVATE KEY", "client private key");
        if (blocks.size() != 1) {
            throw new GeneralSecurityException("client private key must contain exactly one PKCS#8 key");
        }
        return KeyFactory.getInstance(certificate.getPublicKey().getAlgorithm())
                .generatePrivate(new PKCS8EncodedKeySpec(blocks.getFirst()));
    }

    private static String read(Path configured, int maximumBytes, String kind) throws IOException {
        Path path = Objects.requireNonNull(configured, kind + " path").toAbsolutePath().normalize();
        Path mount = path.getParent().toRealPath();
        Path real = path.toRealPath();
        long size = Files.size(real);
        if (!real.startsWith(mount) || !Files.isRegularFile(real) || size < 1
                || size > maximumBytes
                || Files.getPosixFilePermissions(real).stream().anyMatch(WRITE_PERMISSIONS::contains)) {
            throw new IOException(kind + " file is unsafe");
        }
        return Files.readString(real, StandardCharsets.US_ASCII);
    }

    private static List<byte[]> pemBlocks(String pem, String label, String kind)
            throws GeneralSecurityException {
        Pattern pattern = Pattern.compile("-----BEGIN " + Pattern.quote(label)
                + "-----\\s*([A-Za-z0-9+/=\\r\\n]+?)\\s*-----END "
                + Pattern.quote(label) + "-----");
        Matcher matcher = pattern.matcher(pem);
        List<byte[]> result = new ArrayList<>();
        int cursor = 0;
        while (matcher.find()) {
            if (!pem.substring(cursor, matcher.start()).isBlank()) {
                throw new GeneralSecurityException(kind + " contains unexpected PEM data");
            }
            String encoded = matcher.group(1).replaceAll("\\s", "");
            try {
                result.add(Base64.getDecoder().decode(encoded));
            } catch (IllegalArgumentException exception) {
                throw new GeneralSecurityException(kind + " contains invalid base64", exception);
            }
            cursor = matcher.end();
        }
        if (!pem.substring(cursor).isBlank() || result.isEmpty()) {
            throw new GeneralSecurityException(kind + " contains no valid " + label + " PEM block");
        }
        return List.copyOf(result);
    }

    private static void validateClientCertificate(X509Certificate certificate, Clock clock)
            throws GeneralSecurityException {
        certificate.checkValidity(Date.from(clock.instant()));
        if (certificate.getBasicConstraints() >= 0) {
            throw new GeneralSecurityException("mTLS client certificate must not be a CA");
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
            throw new GeneralSecurityException("mTLS client certificate lacks digitalSignature usage");
        }
        List<String> extended = certificate.getExtendedKeyUsage();
        if (extended != null && !extended.contains(CLIENT_AUTH_OID)
                && !extended.contains(ANY_EXTENDED_KEY_USAGE_OID)) {
            throw new GeneralSecurityException("mTLS certificate lacks clientAuth usage");
        }
    }

    private static boolean hasPrivateKey(KeyStore store) throws GeneralSecurityException {
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            if (store.isKeyEntry(aliases.nextElement())) {
                return true;
            }
        }
        return false;
    }

    private static Path configuredPath(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return Path.of(value);
    }

    private static void requirePrefix(String prefix) {
        if (prefix == null || !prefix.matches("ELMPAY_[A-Z0-9_]+")) {
            throw new IllegalArgumentException("mTLS environment prefix is invalid");
        }
    }
}
