package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.security.EnvelopeEncryptionService;
import com.elmpay.security.HttpsKmsClient;
import com.elmpay.security.SecretReference;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class HttpsProviderCredentialResolverTest {
    private static final HttpHeaders JSON_HEADERS = HttpHeaders.of(
            Map.of("Content-Type", List.of("application/json")),
            (name, value) -> true);
    private static final HttpHeaders EMPTY_HEADERS = HttpHeaders.of(Map.of(),
            (name, value) -> true);
    private static final HttpHeaders TEXT_HEADERS = HttpHeaders.of(
            Map.of("Content-Type", List.of("text/plain")), (name, value) -> true);
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000101");
    private static final UUID ACCOUNT = UUID.fromString("00000000-0000-0000-0000-000000000202");
    private static final SecretReference REFERENCE = SecretReference.parse("vault://provider/stripe/a");
    private static final SecretReference KMS_REFERENCE = SecretReference.parse("kms://provider/stripe/live-key");

    @TempDir
    java.nio.file.Path directory;

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
        assertTrue(transport.requests.stream().allMatch(request -> allZero(
                request.bodyReference())));
        assertThrows(IllegalStateException.class, transport.lease::body);
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

        RecordingTransport wrongContent = new RecordingTransport(response(Map.of(
                "tenantId", TENANT.toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", REFERENCE.uri().toString(),
                "credentialVersion", "version-7",
                "leaseId", "lease-123",
                "expiresAt", NOW.plusSeconds(60).toString(),
                "material.api_key", "c2VjcmV0"), TEXT_HEADERS));
        assertThrows(SecurityException.class,
                () -> resolver(wrongContent).resolve(TENANT, ACCOUNT, REFERENCE, "version-7"));
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

        RecordingTransport invalidUtf8 = new RecordingTransport(
                new HttpsProviderCredentialResolver.Response(200, JSON_HEADERS,
                        new byte[] {'{', '"', 'x', '"', ':', '"', (byte) 0xc3,
                                (byte) 0x28, '"', '}'}));
        assertThrows(SecurityException.class,
                () -> resolver(invalidUtf8).resolve(TENANT, ACCOUNT, REFERENCE, "version-7"));
    }

    @Test
    void mountedTokenAcceptsInMountRotationSymlinkAndRejectsEscapeOrWritableValue()
            throws Exception {
        java.nio.file.Path mount = java.nio.file.Files.createDirectory(directory.resolve("mount"));
        java.nio.file.Path data = java.nio.file.Files.createDirectory(mount.resolve("..data"));
        java.nio.file.Path version = data.resolve("token");
        java.nio.file.Files.writeString(version, "rotated-workload-token\n");
        java.nio.file.Files.setPosixFilePermissions(version, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ));
        java.nio.file.Path projected = mount.resolve("token");
        java.nio.file.Files.createSymbolicLink(projected, java.nio.file.Path.of("..data/token"));
        assertEquals("rotated-workload-token",
                HttpsProviderCredentialResolver.readToken(projected));

        java.nio.file.Path outside = directory.resolve("outside-token");
        java.nio.file.Files.writeString(outside, "outside");
        java.nio.file.Files.setPosixFilePermissions(outside, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ));
        java.nio.file.Path escaped = mount.resolve("escaped");
        java.nio.file.Files.createSymbolicLink(escaped, outside);
        assertThrows(SecurityException.class,
                () -> HttpsProviderCredentialResolver.readToken(escaped));

        java.nio.file.Path writable = mount.resolve("writable");
        java.nio.file.Files.writeString(writable, "writable");
        java.nio.file.Files.setPosixFilePermissions(writable, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        assertThrows(SecurityException.class,
                () -> HttpsProviderCredentialResolver.readToken(writable));
    }

    @Test
    void requestBytesAreWipedWhenCredentialTransportFails() {
        AtomicReference<byte[]> captured = new AtomicReference<>();
        HttpsProviderCredentialResolver resolver = new HttpsProviderCredentialResolver(
                URI.create("https://vault.internal.example/"),
                (endpoint, headers, body, timeout) -> {
                    captured.set(body);
                    throw new IllegalStateException("unavailable");
                }, () -> "workload-token", Duration.ofSeconds(2), Duration.ofMinutes(5),
                Clock.fixed(NOW, ZoneOffset.UTC));
        assertThrows(IllegalStateException.class,
                () -> resolver.resolve(TENANT, ACCOUNT, REFERENCE, "version-7"));
        assertTrue(allZero(captured.get()));
    }

    @Test
    void productionCompositionRejectsInlineLegacyAndPartialCredentialConfiguration() {
        assertThrows(IllegalStateException.class,
                () -> HttpsProviderCredentialResolver.fromEnvironment(Map.of(
                        "ELMPAY_PROVIDER_CREDENTIAL_ACCESS_TOKEN", "inline-forbidden"),
                        Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(IllegalStateException.class,
                () -> HttpsProviderCredentialResolver.fromEnvironment(Map.of(
                        "ELMPAY_PROVIDER_CREDENTIAL_ENDPOINT",
                        "https://vault.internal.example/"),
                        Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(IllegalStateException.class,
                () -> HttpsProviderCredentialResolver.fromEnvironment(Map.of(
                        "ELMPAY_PROVIDER_CREDENTIAL_TOKEN_FILE", "/tmp/legacy-token"),
                        Clock.fixed(NOW, ZoneOffset.UTC)));
    }

    @Test
    void kmsEnvelopeLeaseUnwrapsThroughHttpsKmsAndRejectsAadOrPlaintextDowngrade() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        byte[] dataKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] wrappedDataKey = "wrapped-kms-data-key-material-0123456789".getBytes(StandardCharsets.UTF_8);
        String b64DataKey = Base64.getUrlEncoder().withoutPadding().encodeToString(dataKey);
        String b64Wrapped = Base64.getUrlEncoder().withoutPadding().encodeToString(wrappedDataKey);
        List<String> kmsPaths = new ArrayList<>();
        HttpsKmsClient kmsClient = new HttpsKmsClient(
                URI.create("https://kms.internal.example/v1"),
                (endpoint, headers, body, timeout) -> {
                    kmsPaths.add(endpoint.getPath());
                    String payload = endpoint.getPath().endsWith("/generate")
                            ? "{\"keyReference\":\"" + KMS_REFERENCE.uri()
                                    + "\",\"keyVersion\":\"kv-9\",\"plaintextKey\":\""
                                    + b64DataKey + "\",\"wrappedDataKey\":\"" + b64Wrapped
                                    + "\",\"plaintextExpiresAt\":\"" + NOW.plusSeconds(5) + "\"}"
                            : "{\"plaintextKey\":\"" + b64DataKey
                                    + "\",\"plaintextExpiresAt\":\"" + NOW.plusSeconds(5) + "\"}";
                    return new HttpsKmsClient.Response(200, JSON_HEADERS,
                            payload.getBytes(StandardCharsets.UTF_8));
                },
                () -> "kms-workload-token",
                Duration.ofSeconds(2));
        EnvelopeEncryptionService envelopeService = new EnvelopeEncryptionService(
                kmsClient, clock, new SecureRandom(), Duration.ofSeconds(5));
        EnvelopeEncryptionService.Envelope sealed = envelopeService.encrypt(
                KMS_REFERENCE.uri().toString(),
                "kms-sealed-stripe-secret".getBytes(StandardCharsets.UTF_8),
                HttpsProviderCredentialResolver.credentialEnvelopeAad(
                        TENANT, ACCOUNT, KMS_REFERENCE, "version-9", "api_key"));

        Map<String, String> leaseFields = new LinkedHashMap<>();
        leaseFields.put("tenantId", TENANT.toString());
        leaseFields.put("providerAccountId", ACCOUNT.toString());
        leaseFields.put("secretReference", KMS_REFERENCE.uri().toString());
        leaseFields.put("credentialVersion", "version-9");
        leaseFields.put("leaseId", "lease-kms-9");
        leaseFields.put("expiresAt", NOW.plusSeconds(60).toString());
        leaseFields.put("envelope.api_key.keyReference", sealed.keyReference());
        leaseFields.put("envelope.api_key.keyVersion", sealed.keyVersion());
        leaseFields.put("envelope.api_key.wrappedDataKey",
                Base64.getUrlEncoder().withoutPadding().encodeToString(sealed.wrappedDataKey()));
        leaseFields.put("envelope.api_key.nonce",
                Base64.getUrlEncoder().withoutPadding().encodeToString(sealed.nonce()));
        leaseFields.put("envelope.api_key.ciphertext",
                Base64.getUrlEncoder().withoutPadding().encodeToString(sealed.ciphertext()));
        leaseFields.put("envelope.api_key.aadDigest",
                Base64.getUrlEncoder().withoutPadding().encodeToString(sealed.aadDigest()));
        leaseFields.put("envelope.api_key.createdAt", sealed.createdAt().toString());

        RecordingTransport transport = new RecordingTransport(response(leaseFields));
        HttpsProviderCredentialResolver kmsResolver = new HttpsProviderCredentialResolver(
                URI.create("https://vault.internal.example/"),
                transport, () -> "workload-token", Duration.ofSeconds(2),
                Duration.ofMinutes(5), clock, envelopeService);

        try (SecretMaterialProviderCredential credential = (SecretMaterialProviderCredential)
                kmsResolver.resolve(TENANT, ACCOUNT, KMS_REFERENCE, "version-9")) {
            assertEquals("kms-sealed-stripe-secret",
                    credential.use("api_key", bytes -> new String(bytes, StandardCharsets.UTF_8)));
        }
        assertEquals(List.of("/v1/data-keys/generate", "/v1/data-keys/unwrap"), kmsPaths);
        assertEquals(2, transport.requests.size());

        // Plaintext material downgrade on a kms:// reference must fail closed.
        RecordingTransport downgrade = new RecordingTransport(response(Map.of(
                "tenantId", TENANT.toString(),
                "providerAccountId", ACCOUNT.toString(),
                "secretReference", KMS_REFERENCE.uri().toString(),
                "credentialVersion", "version-9",
                "leaseId", "lease-downgrade",
                "expiresAt", NOW.plusSeconds(60).toString(),
                "material.api_key", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("downgraded".getBytes(StandardCharsets.UTF_8)))));
        HttpsProviderCredentialResolver downgradeResolver = new HttpsProviderCredentialResolver(
                URI.create("https://vault.internal.example/"),
                downgrade, () -> "workload-token", Duration.ofSeconds(2),
                Duration.ofMinutes(5), clock, envelopeService);
        assertThrows(SecurityException.class,
                () -> downgradeResolver.resolve(TENANT, ACCOUNT, KMS_REFERENCE, "version-9"));

        // Envelope sealed for version-9 replayed under version-10 must fail AAD verification.
        Map<String, String> replayedVersion = new LinkedHashMap<>(leaseFields);
        replayedVersion.put("credentialVersion", "version-10");
        HttpsProviderCredentialResolver replayResolver = new HttpsProviderCredentialResolver(
                URI.create("https://vault.internal.example/"),
                new RecordingTransport(response(replayedVersion)),
                () -> "workload-token", Duration.ofSeconds(2),
                Duration.ofMinutes(5), clock, envelopeService);
        assertThrows(SecurityException.class,
                () -> replayResolver.resolve(TENANT, ACCOUNT, KMS_REFERENCE, "version-10"));
    }

    private static HttpsProviderCredentialResolver resolver(RecordingTransport transport) {
        return new HttpsProviderCredentialResolver(URI.create("https://vault.internal.example/"),
                transport, () -> "workload-token", Duration.ofSeconds(2),
                Duration.ofMinutes(5), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static HttpsProviderCredentialResolver.Response response(Map<String, String> values) {
        return response(values, JSON_HEADERS);
    }

    private static HttpsProviderCredentialResolver.Response response(Map<String, String> values,
            HttpHeaders headers) {
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
        return new HttpsProviderCredentialResolver.Response(200, headers,
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
            requests.add(new Request(endpoint, new String(body, StandardCharsets.UTF_8), body));
            if (endpoint.getPath().endsWith("/revoke")) {
                return new HttpsProviderCredentialResolver.Response(
                        revokeStatus, EMPTY_HEADERS, new byte[0]);
            }
            return lease;
        }
    }

    private static boolean allZero(byte[] value) {
        for (byte item : value) {
            if (item != 0) {
                return false;
            }
        }
        return true;
    }

    private record Request(URI uri, String body, byte[] bodyReference) {}
}
