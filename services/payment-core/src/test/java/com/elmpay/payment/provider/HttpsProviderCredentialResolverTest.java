package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.security.SecretReference;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class HttpsProviderCredentialResolverTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000101");
    private static final UUID ACCOUNT = UUID.fromString("00000000-0000-0000-0000-000000000202");
    private static final SecretReference REFERENCE = SecretReference.parse("vault://provider/stripe/a");

    @Test
    void exactBoundShortLeaseIsUsableRevokedAndWiped() {
        RecordingTransport transport = new RecordingTransport(response(Map.of(
                "tenantId", TENANT.toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", REFERENCE.uri().toString(),
                "credentialVersion", "version-7",
                "leaseId", "lease-123",
                "expiresAt", NOW.plusSeconds(60).toString(),
                "material.api_key", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("top-secret".getBytes(StandardCharsets.UTF_8)))));
        HttpsProviderCredentialResolver resolver = resolver(transport);

        ProviderCredential opaque = resolver.resolve(TENANT, ACCOUNT, REFERENCE, "version-7");
        SecretMaterialProviderCredential credential =
                (SecretMaterialProviderCredential) opaque;
        assertEquals("version-7", credential.version());
        assertEquals("lease-123", credential.leaseId());
        assertArrayEquals("top-secret".getBytes(StandardCharsets.UTF_8),
                credential.require("api_key"));
        byte[] leakedCopy = credential.require("api_key");
        leakedCopy[0] = 0;
        assertEquals("top-secret", credential.use("api_key",
                bytes -> new String(bytes, StandardCharsets.UTF_8)));
        assertFalse(credential.toString().contains("top-secret"));

        credential.close();
        credential.close();
        assertThrows(IllegalStateException.class, () -> credential.require("api_key"));
        assertEquals(2, transport.requests.size());
        assertTrue(transport.requests.getFirst().uri().getPath().endsWith("/lease"));
        assertTrue(transport.requests.getLast().uri().getPath().endsWith("/revoke"));
        assertTrue(transport.requests.getFirst().body().contains(TENANT.toString()));
        assertTrue(transport.requests.getFirst().body().contains(ACCOUNT.toString()));
        assertTrue(transport.requests.getFirst().body().contains("version-7"));
    }

    @Test
    void responseBindingAndLeaseBoundsFailClosed() {
        RecordingTransport wrongTenant = new RecordingTransport(response(Map.of(
                "tenantId", UUID.randomUUID().toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", REFERENCE.uri().toString(),
                "credentialVersion", "version-7",
                "leaseId", "lease-123",
                "expiresAt", NOW.plusSeconds(60).toString(),
                "material.api_key", "c2VjcmV0")));
        assertThrows(SecurityException.class,
                () -> resolver(wrongTenant).resolve(TENANT, ACCOUNT, REFERENCE, "version-7"));

        RecordingTransport excessive = new RecordingTransport(response(Map.of(
                "tenantId", TENANT.toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", REFERENCE.uri().toString(),
                "credentialVersion", "version-7",
                "leaseId", "lease-123",
                "expiresAt", NOW.plusSeconds(301).toString(),
                "material.api_key", "c2VjcmV0")));
        assertThrows(SecurityException.class,
                () -> resolver(excessive).resolve(TENANT, ACCOUNT, REFERENCE, "version-7"));
    }

    @Test
    void malformedMaterialAndFailedRevocationNeverExposeOrRetainAUsableLease() {
        RecordingTransport malformed = new RecordingTransport(response(Map.of(
                "tenantId", TENANT.toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", REFERENCE.uri().toString(),
                "credentialVersion", "version-7",
                "leaseId", "lease-123",
                "expiresAt", NOW.plusSeconds(60).toString(),
                "material.api_key", "%%%")));
        assertThrows(SecurityException.class,
                () -> resolver(malformed).resolve(TENANT, ACCOUNT, REFERENCE, "version-7"));

        RecordingTransport failedRevoke = new RecordingTransport(response(Map.of(
                "tenantId", TENANT.toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", REFERENCE.uri().toString(),
                "credentialVersion", "version-7",
                "leaseId", "lease-123",
                "expiresAt", NOW.plusSeconds(60).toString(),
                "material.api_key", "c2VjcmV0")));
        failedRevoke.revokeStatus = 503;
        SecretMaterialProviderCredential credential = (SecretMaterialProviderCredential)
                resolver(failedRevoke).resolve(TENANT, ACCOUNT, REFERENCE, "version-7");
        assertThrows(IllegalStateException.class, credential::close);
        assertThrows(IllegalStateException.class, () -> credential.require("api_key"));
    }

    private static HttpsProviderCredentialResolver resolver(RecordingTransport transport) {
        return new HttpsProviderCredentialResolver(URI.create("https://vault.internal.example/"),
                transport, () -> "workload-token", Duration.ofSeconds(2),
                Duration.ofMinutes(5), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static HttpsProviderCredentialResolver.Response response(Map<String, String> values) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : new java.util.TreeMap<>(values).entrySet()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('"').append(entry.getKey()).append("\":\"")
                    .append(entry.getValue()).append('"');
        }
        return new HttpsProviderCredentialResolver.Response(200,
                json.append('}').toString().getBytes(StandardCharsets.UTF_8));
    }

    private static final class RecordingTransport
            implements HttpsProviderCredentialResolver.Transport {
        private final HttpsProviderCredentialResolver.Response lease;
        private final List<Request> requests = new ArrayList<>();
        private int revokeStatus = 204;

        private RecordingTransport(HttpsProviderCredentialResolver.Response lease) {
            this.lease = lease;
        }

        @Override
        public HttpsProviderCredentialResolver.Response post(URI endpoint,
                Map<String, String> headers, byte[] body, Duration timeout) {
            requests.add(new Request(endpoint, new String(body, StandardCharsets.UTF_8)));
            if (endpoint.getPath().endsWith("/revoke")) {
                return new HttpsProviderCredentialResolver.Response(revokeStatus, new byte[0]);
            }
            return lease;
        }
    }

    private record Request(URI uri, String body) {}
}
