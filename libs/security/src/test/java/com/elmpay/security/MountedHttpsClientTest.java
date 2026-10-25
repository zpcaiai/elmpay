package com.elmpay.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class MountedHttpsClientTest {
    @TempDir
    static Path pkiRoot;
    @TempDir
    Path root;
    private static TlsTestMaterial material;

    @BeforeAll
    static void generateRealEphemeralPki() throws Exception {
        material = new TlsTestMaterial(pkiRoot);
    }

    private static MountedHttpsClient.Client load(Path mount, Clock clock, Duration timeout) {
        return MountedHttpsClient.loadForTest(mount.resolve("tls.crt"), mount.resolve("tls.key"),
                mount.resolve("ca.crt"), mount.resolve("token"), clock, timeout);
    }

    private static MountedHttpsClient.Client load(Path mount) {
        return load(mount, Clock.systemUTC(), Duration.ofSeconds(2));
    }

    @Test
    void realTls13RequiresAndAuthenticatesMountedClientCertificate() throws Exception {
        Path mount = material.mount(root);
        // The complete client chain is validated and used by the real TLS provider.
        byte[] chain = concatenate(material.certificate("client"), material.certificate("root"));
        TlsTestMaterial.readOnly(mount.resolve("tls.crt"), chain);
        SSLContext serverContext = material.serverContext();
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> peer = new AtomicReference<>();
        AtomicReference<String> protocol = new AtomicReference<>();
        AtomicInteger redirected = new AtomicInteger();
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext) {
            @Override
            public void configure(HttpsParameters parameters) {
                SSLParameters ssl = serverContext.getDefaultSSLParameters();
                ssl.setProtocols(new String[] {"TLSv1.3"});
                ssl.setNeedClientAuth(true);
                parameters.setSSLParameters(ssl);
            }
        });
        server.createContext("/paid", exchange -> {
            redirected.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/", exchange -> {
            try {
                HttpsExchange https = (HttpsExchange) exchange;
                peer.set(https.getSSLSession().getPeerPrincipal().getName());
                protocol.set(https.getSSLSession().getProtocol());
                if (exchange.getRequestURI().getPath().equals("/redirect")) {
                    exchange.getResponseHeaders().set("Location", "/paid");
                    exchange.sendResponseHeaders(302, -1);
                } else {
                    byte[] response = "mutual TLS authenticated".getBytes(StandardCharsets.US_ASCII);
                    exchange.sendResponseHeaders(200, response.length);
                    exchange.getResponseBody().write(response);
                }
            } finally {
                exchange.close();
            }
        });
        server.start();
        try (HttpClient client = load(mount).httpClient()) {
            URI origin = URI.create("https://localhost:" + server.getAddress().getPort());
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                    origin.resolve("/handshake")).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertEquals("mutual TLS authenticated", response.body());
            assertEquals("CN=elmpay-test-client", peer.get());
            assertEquals("TLSv1.3", protocol.get());
            assertEquals(302, client.send(HttpRequest.newBuilder(origin.resolve("/redirect"))
                    .timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode());
            assertEquals(0, redirected.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void configuredClientRetainsExactTransportAndRotatingTokenBoundaries() throws Exception {
        Path mount = material.mount(root);
        MountedHttpsClient.Client mounted = load(mount);
        try (HttpClient client = mounted.httpClient()) {
            assertEquals(HttpClient.Redirect.NEVER, client.followRedirects());
            assertEquals(HttpClient.Version.HTTP_1_1, client.version());
            assertEquals(Duration.ofSeconds(2), client.connectTimeout().orElseThrow());
            assertEquals(List.of("TLSv1.3"), Arrays.asList(client.sslParameters().getProtocols()));
            assertEquals("HTTPS", client.sslParameters().getEndpointIdentificationAlgorithm());
            assertEquals("a".repeat(48), mounted.accessToken().get());
            TlsTestMaterial.readOnly(mount.resolve("token"),
                    ("b".repeat(48) + "==\r\n").getBytes(StandardCharsets.US_ASCII));
            assertEquals("b".repeat(48) + "==", mounted.accessToken().get());
        }
    }

    @Test
    void projectedSecretRotationResolvesTheNewReadOnlyTarget() throws Exception {
        Path mount = material.mount(root);
        Path version1 = Files.createDirectory(mount.resolve("version1"));
        Path version2 = Files.createDirectory(mount.resolve("version2"));
        TlsTestMaterial.readOnly(version1.resolve("token"),
                "x".repeat(32).getBytes(StandardCharsets.US_ASCII));
        TlsTestMaterial.readOnly(version2.resolve("token"),
                "y".repeat(32).getBytes(StandardCharsets.US_ASCII));
        Files.delete(mount.resolve("token"));
        Files.createSymbolicLink(mount.resolve("..data"), Path.of("version1"));
        Files.createSymbolicLink(mount.resolve("token"), Path.of("..data/token"));
        MountedHttpsClient.Client mounted = load(mount);
        try (HttpClient ignored = mounted.httpClient()) {
            assertNotNull(ignored.sslContext());
            assertEquals("x".repeat(32), mounted.accessToken().get());
            Files.createSymbolicLink(mount.resolve("..next"), Path.of("version2"));
            Files.move(mount.resolve("..next"), mount.resolve("..data"),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            assertEquals("y".repeat(32), mounted.accessToken().get());
        }
    }

    @Test
    void expiredAndNotYetValidCertificatesFailBeforeAClientIsReturned() throws Exception {
        Path mount = material.mount(root);
        for (Instant invalid : List.of(Instant.now().minus(Duration.ofDays(3)),
                Instant.now().plus(Duration.ofDays(3)))) {
            assertThrows(IllegalStateException.class, () -> load(mount,
                    Clock.fixed(invalid, ZoneOffset.UTC), Duration.ofSeconds(2)));
        }
    }

    @Test
    void certificateMustBeClientAuthLeafAndMatchItsActualPrivateKey() throws Exception {
        Path mount = material.mount(root);
        TlsTestMaterial.readOnly(mount.resolve("tls.crt"), material.certificate("server"));
        assertThrows(IllegalStateException.class, () -> load(mount));
        TlsTestMaterial.readOnly(mount.resolve("tls.crt"), material.certificate("root"));
        assertThrows(IllegalStateException.class, () -> load(mount));
        TlsTestMaterial.readOnly(mount.resolve("tls.crt"), material.certificate("client"));
        TlsTestMaterial.readOnly(mount.resolve("tls.key"), material.key("server"));
        assertThrows(IllegalStateException.class, () -> load(mount));
    }

    @Test
    void duplicateAndUnorderedClientChainsAreDenied() throws Exception {
        Path mount = material.mount(root);
        for (byte[] chain : List.of(
                concatenate(material.certificate("client"), material.certificate("client")),
                concatenate(material.certificate("root"), material.certificate("client")),
                concatenate(material.certificate("client"), material.certificate("server")))) {
            TlsTestMaterial.readOnly(mount.resolve("tls.crt"), chain);
            assertThrows(IllegalStateException.class, () -> load(mount));
        }
    }

    @Test
    void trustBundleRequiresUniqueRealCertificateAuthorities() throws Exception {
        Path mount = material.mount(root);
        for (byte[] trust : List.of(material.certificate("client"),
                concatenate(material.certificate("root"), material.certificate("root")),
                new byte[0], "not a certificate".getBytes(StandardCharsets.US_ASCII))) {
            TlsTestMaterial.readOnly(mount.resolve("ca.crt"), trust);
            assertThrows(IllegalStateException.class, () -> load(mount));
        }
    }

    @Test
    void privateKeyRequiresExactlyOneCanonicalPkcs8PemValue() throws Exception {
        Path mount = material.mount(root);
        byte[] valid = material.key("client");
        String pem = new String(valid, StandardCharsets.US_ASCII);
        for (byte[] invalid : List.of(new byte[0], concatenate(valid, valid),
                (pem + "trailing").getBytes(StandardCharsets.US_ASCII),
                pem.replace("END PRIVATE KEY", "END RSA PRIVATE KEY")
                        .getBytes(StandardCharsets.US_ASCII),
                pem.replaceFirst("\n", "\n!").getBytes(StandardCharsets.US_ASCII))) {
            TlsTestMaterial.readOnly(mount.resolve("tls.key"), invalid);
            assertThrows(IllegalStateException.class, () -> load(mount));
        }
        TlsTestMaterial.readOnly(mount.resolve("tls.key"),
                ("\r\n" + pem + "\r\n").getBytes(StandardCharsets.US_ASCII));
        try (HttpClient client = load(mount).httpClient()) {
            assertNotNull(client.sslContext());
        }
    }

    @Test
    void token68LengthPaddingAndLineEndingRulesAreEnforcedOnEveryRead() throws Exception {
        Path token = root.resolve("token");
        for (String valid : List.of("a".repeat(32), "a".repeat(8192),
                "Az09-._~+/".repeat(4) + "==", "a".repeat(32) + "\n",
                "a".repeat(32) + "\r\n")) {
            TlsTestMaterial.readOnly(token, valid.getBytes(StandardCharsets.US_ASCII));
            assertEquals(valid.stripTrailing(), MountedHttpsClient.readTokenForTest(token));
        }
        for (String invalid : List.of("a".repeat(31), "a".repeat(8193), "=".repeat(32),
                "a".repeat(31) + " ", "a".repeat(31) + ":", "a".repeat(16) + "="
                        + "b".repeat(16), "a".repeat(32) + "\n\n", "a".repeat(32) + "\r")) {
            TlsTestMaterial.readOnly(token, invalid.getBytes(StandardCharsets.US_ASCII));
            assertThrows(RuntimeException.class, () -> MountedHttpsClient.readTokenForTest(token));
        }
        TlsTestMaterial.readOnly(token, ("a".repeat(32) + "é").getBytes(StandardCharsets.UTF_8));
        assertThrows(SecurityException.class, () -> MountedHttpsClient.readTokenForTest(token));
    }

    @Test
    void writableOversizedMissingAndEscapedMountFilesAreDenied() throws Exception {
        Path mount = material.mount(root);
        Path token = mount.resolve("token");
        Files.setPosixFilePermissions(token, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        assertThrows(IllegalStateException.class, () -> load(mount));
        TlsTestMaterial.readOnly(token, new byte[8193]);
        assertThrows(IllegalStateException.class, () -> load(mount));
        Files.delete(token);
        assertThrows(IllegalStateException.class, () -> load(mount));
        Path outside = root.resolve("outside-token");
        TlsTestMaterial.readOnly(outside, "a".repeat(48).getBytes(StandardCharsets.US_ASCII));
        Files.createSymbolicLink(token, outside);
        assertThrows(IllegalStateException.class, () -> load(mount));
        assertThrows(IllegalArgumentException.class, () -> MountedHttpsClient.loadForTest(
                mount.resolve("tls.crt"), mount.resolve("tls.key"), mount.resolve("ca.crt"),
                outside, Clock.systemUTC(), Duration.ofSeconds(2)));
    }

    @Test
    void startupRejectsMalformedTokenAndNonExactCertificateFilename() throws Exception {
        Path mount = material.mount(root);
        TlsTestMaterial.readOnly(mount.resolve("token"), "a".repeat(31)
                .getBytes(StandardCharsets.US_ASCII));
        assertThrows(SecurityException.class, () -> load(mount));
        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.loadForTest(
                mount.resolve("renamed.crt"), mount.resolve("tls.key"), mount.resolve("ca.crt"),
                mount.resolve("token"), Clock.systemUTC(), Duration.ofSeconds(2)));
    }

    @Test
    void invalidTimeoutsAndPublicEnvironmentBindingsFailBeforeMountAccess() throws Exception {
        Path mount = material.mount(root);
        for (Duration invalid : List.of(Duration.ZERO, Duration.ofNanos(-1),
                Duration.ofSeconds(10).plusNanos(1))) {
            assertThrows(IllegalArgumentException.class, () -> load(mount, Clock.systemUTC(), invalid));
        }
        assertThrows(NullPointerException.class, () -> load(mount, Clock.systemUTC(), null));
        for (String invalidPrefix : List.of("", "PAY", "ELMPAY_lower", "ELMPAY_A/B")) {
            assertThrows(IllegalArgumentException.class, () -> MountedHttpsClient.fromEnvironment(
                    Map.of(), invalidPrefix, "runtime", Clock.systemUTC(), Duration.ofSeconds(1)));
        }
        for (String invalidMount : List.of("", "../runtime", "Runtime", "a/b", "-a")) {
            assertThrows(IllegalArgumentException.class, () -> MountedHttpsClient.fromEnvironment(
                    Map.of(), "ELMPAY_TEST", invalidMount, Clock.systemUTC(), Duration.ofSeconds(1)));
        }
        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.fromEnvironment(
                Map.of("ELMPAY_TEST_MTLS", "true"), "ELMPAY_TEST", "runtime", Clock.systemUTC(),
                Duration.ofSeconds(1)));
        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.fromEnvironment(
                Map.of("ELMPAY_TEST_MTLS_CLIENT_CERT_FILE", mount.resolve("tls.crt").toString()),
                "ELMPAY_TEST", "runtime", Clock.systemUTC(), Duration.ofSeconds(1)));
        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.mutualTlsContextFromEnvironment(
                Map.of(), "ELMPAY_TEST", "runtime", Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> MountedHttpsClient.readExactMountedFile(
                Map.of(), "UNSAFE", "runtime", "token", 10));
        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.readExactMountedFile(
                Map.of("ELMPAY_TEST_FILE", "relative/token"), "ELMPAY_TEST_FILE", "runtime", "token", 10));
        assertFalse(Files.exists(Path.of("/var/run/secrets/elmpay/runtime")));
    }

    @Test
    void publicClientRecordRejectsAbsentTransportOrTokenSupplier() {
        assertThrows(NullPointerException.class, () -> new MountedHttpsClient.Client(null, () -> ""));
        try (HttpClient client = HttpClient.newHttpClient()) {
            assertThrows(NullPointerException.class, () -> new MountedHttpsClient.Client(client, null));
            assertThrows(SecurityException.class, () -> new MountedHttpsClient.Client(client,
                    () -> "a".repeat(32)));
        }
    }

    private static byte[] concatenate(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
