package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

final class DemoCredentialInteropTest {
    @Test
    void actualNodeDemoVerifierAuthenticatesOnlyTheCorrectBearerOverHttp() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isRegularFile(root.resolve("settings.gradle.kts"))) {
            root = root.getParent();
        }
        assertTrue(root != null, "repository root must be available");
        Process generator = new ProcessBuilder("node", "--input-type=module", "-e", """
                import { demoConfiguration } from './apps/free-demo/src/bridge.mjs';
                const config = demoConfiguration({ELMPAY_DEMO_ENABLED:'true',
                  ELMPAY_DEMO_REAL_PAYMENTS_DISABLED:'true'});
                console.log(JSON.stringify({credential:config.apiToken,
                  principals:config.childEnvironment.ELMPAY_API_PRINCIPALS}));
                """).directory(root.toFile()).redirectErrorStream(true).start();
        try {
            assertTrue(generator.waitFor(30, TimeUnit.SECONDS), "bounded demo generator must finish");
            assertEquals(0, generator.exitValue());
            byte[] output = generator.getInputStream().readNBytes(4097);
            assertTrue(output.length <= 4096, "bounded generator output required");
            Map<String, Object> configuration = Json.object(new String(output, StandardCharsets.UTF_8));
            String credential = (String) configuration.get("credential");
            String principals = (String) configuration.get("principals");
            assertTrue(principals.startsWith("pbkdf2-sha256:600000:"));
            assertTrue(!principals.contains(credential));
            ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.parse(principals);
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 8);
            server.createContext("/", exchange -> {
                int status = authenticator.authenticate(exchange).isPresent() ? 200 : 401;
                exchange.sendResponseHeaders(status, -1);
                exchange.close();
            });
            server.start();
            try {
                URI address = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
                HttpClient client = HttpClient.newHttpClient();
                assertEquals(200, client.send(HttpRequest.newBuilder(address).timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + credential).GET().build(),
                        HttpResponse.BodyHandlers.discarding()).statusCode());
                assertEquals(401, client.send(HttpRequest.newBuilder(address).timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + UUID.randomUUID()).GET().build(),
                        HttpResponse.BodyHandlers.discarding()).statusCode());
                assertEquals(401, client.send(HttpRequest.newBuilder(address).timeout(Duration.ofSeconds(10))
                        .headers("Authorization", "Bearer " + credential,
                                "Authorization", "Bearer " + credential).GET().build(),
                        HttpResponse.BodyHandlers.discarding()).statusCode());
            } finally {
                server.stop(0);
            }
            assertThrows(IllegalStateException.class, () -> RuntimeFactory.create(Map.of(
                    "ELMPAY_RUNTIME_MODE", "postgres", "ELMPAY_API_PRINCIPALS", principals)));
        } finally {
            if (generator.isAlive()) generator.destroyForcibly();
        }
    }

    @Test
    void malformedOrWeakenedVerifiersNeverFallBackToLegacyAuthentication() {
        String identity = "|demo|21000000-0000-4000-8000-000000000001"
                + "|21000000-0000-4000-8000-000000000002"
                + "|21000000-0000-4000-8000-000000000003|payments.read+payments.write";
        String salt = "ab".repeat(16);
        String digest = "cd".repeat(32);
        for (String verifier : new String[] {
                "pbkdf2-sha256:599999:" + salt + ":" + digest,
                "pbkdf2-sha256:999999999:" + salt + ":" + digest,
                "pbkdf2-sha256:600000:ab:" + digest,
                "pbkdf2-sha256:600000:" + salt + ":cd",
                "pbkdf2-sha1:600000:" + salt + ":" + digest,
                "pbkdf2-sha256:600000:" + salt + ":" + digest + ":extra" }) {
            assertThrows(IllegalArgumentException.class, () -> ApiKeyAuthenticator.parse(verifier + identity));
        }
    }
}
