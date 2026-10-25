package com.elmpay.security;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Real, ephemeral test PKI. No checked-in key material or replaced TLS provider. */
final class TlsTestMaterial {
    private final Path root;
    private int commandIndex;

    TlsTestMaterial(Path root) throws Exception {
        this.root = root;
        Files.setPosixFilePermissions(root, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
        Files.writeString(root.resolve("root.cnf"), """
                [req]
                distinguished_name=dn
                x509_extensions=ca
                prompt=no
                [dn]
                CN=ELMPay ephemeral test root
                [ca]
                basicConstraints=critical,CA:TRUE
                keyUsage=critical,keyCertSign,cRLSign
                subjectKeyIdentifier=hash
                """, StandardCharsets.US_ASCII);
        run("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-keyout", "root.key", "-out", "root.crt", "-config", "root.cnf");
        leaf("client", "clientAuth", "1");
        leaf("server", "serverAuth", "2");
    }

    private void leaf(String name, String purpose, String serial) throws Exception {
        Files.writeString(root.resolve(name + ".cnf"), """
                [leaf]
                basicConstraints=critical,CA:FALSE
                keyUsage=critical,digitalSignature,keyEncipherment
                extendedKeyUsage=%s
                subjectAltName=DNS:localhost,IP:127.0.0.1
                """.formatted(purpose), StandardCharsets.US_ASCII);
        run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", name + ".key");
        run("req", "-new", "-key", name + ".key", "-out", name + ".csr", "-subj",
                "/CN=elmpay-test-" + name);
        run("x509", "-req", "-in", name + ".csr", "-CA", "root.crt", "-CAkey",
                "root.key", "-set_serial", serial, "-days", "2", "-extfile",
                name + ".cnf", "-extensions", "leaf", "-out", name + ".crt");
    }

    private void run(String... arguments) throws Exception {
        Path executable = Path.of("/usr/bin/openssl").toRealPath();
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(executable);
        if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)
                || permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
            throw new IllegalStateException("system OpenSSL executable is not trusted");
        }
        List<String> command = new ArrayList<>();
        command.add(executable.toString());
        command.addAll(List.of(arguments));
        Path output = Files.createFile(root.resolve("openssl-" + commandIndex++ + ".log"));
        Files.setPosixFilePermissions(output, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        Process process = new ProcessBuilder(command).directory(root.toFile())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly().waitFor();
            throw new IllegalStateException("ephemeral test PKI command timed out");
        }
        if (process.exitValue() != 0) {
            throw new IllegalStateException("ephemeral test PKI command failed: "
                    + arguments[0] + "; exit=" + process.exitValue());
        }
    }

    byte[] certificate(String name) throws Exception {
        return Files.readAllBytes(root.resolve(name + ".crt"));
    }

    byte[] key(String name) throws Exception {
        return Files.readAllBytes(root.resolve(name + ".key"));
    }

    Path mount(Path parent) throws Exception {
        Path mount = Files.createDirectory(parent.resolve("mount"));
        readOnly(mount.resolve("tls.crt"), certificate("client"));
        readOnly(mount.resolve("tls.key"), key("client"));
        readOnly(mount.resolve("ca.crt"), certificate("root"));
        readOnly(mount.resolve("token"), "a".repeat(48).getBytes(StandardCharsets.US_ASCII));
        return mount;
    }

    static void readOnly(Path path, byte[] bytes) throws Exception {
        if (Files.exists(path)) {
            Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        }
        Files.write(path, bytes);
        Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ));
    }

    SSLContext serverContext() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate server = factory.generateCertificate(new ByteArrayInputStream(
                certificate("server")));
        Certificate ca = factory.generateCertificate(new ByteArrayInputStream(certificate("root")));
        byte[] encoded = key("server");
        byte[] der = Base64.getDecoder().decode(new String(encoded, StandardCharsets.US_ASCII)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", ""));
        char[] password = new char[0];
        try {
            KeyStore identity = KeyStore.getInstance("PKCS12");
            identity.load(null, password);
            identity.setKeyEntry("server", KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(der)), password, new Certificate[] {server, ca});
            KeyManagerFactory keys = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keys.init(identity, password);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("root", ca);
            TrustManagerFactory trusts = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trusts.init(trust);
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keys.getKeyManagers(), trusts.getTrustManagers(), new SecureRandom());
            return context;
        } finally {
            Arrays.fill(encoded, (byte) 0);
            Arrays.fill(der, (byte) 0);
            Arrays.fill(password, '\0');
        }
    }
}
