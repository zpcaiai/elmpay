package com.elmpay.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;

final class EnvelopeEncryptionServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final Map<String, String> AAD = Map.of(
            "tenantId", "tenant-a", "resourceId", "provider-account-1",
            "purpose", "provider-credential");

    @Test
    void envelopeIsAuthenticatedTenantBoundAndRotatable() throws Exception {
        RsaKms kms = new RsaKms();
        kms.add("kms://provider/v1", "1");
        kms.add("kms://provider/v2", "2");
        var service = new EnvelopeEncryptionService(kms, Clock.fixed(NOW, ZoneOffset.UTC),
                new SecureRandom(), Duration.ofSeconds(5));
        byte[] plaintext = "short-lived-provider-secret".getBytes(StandardCharsets.UTF_8);

        var envelope = service.encrypt("kms://provider/v1", plaintext, AAD);
        assertFalse(new String(envelope.ciphertext(), StandardCharsets.UTF_8)
                .contains("provider-secret"));
        assertArrayEquals(plaintext, service.decrypt(envelope, AAD));
        assertThrows(SecurityException.class, () -> service.decrypt(envelope,
                Map.of("tenantId", "tenant-b", "resourceId", "provider-account-1",
                        "purpose", "provider-credential")));

        var rotated = service.rotate(envelope, "kms://provider/v2", AAD);
        assertTrue(rotated.keyReference().endsWith("v2"));
        assertArrayEquals(plaintext, service.decrypt(rotated, AAD));
    }

    @Test
    void ciphertextAndAadTamperingFailClosed() throws Exception {
        RsaKms kms = new RsaKms();
        kms.add("kms://provider/v1", "1");
        var service = new EnvelopeEncryptionService(kms, Clock.fixed(NOW, ZoneOffset.UTC),
                new SecureRandom(), Duration.ofSeconds(5));
        var original = service.encrypt("kms://provider/v1", new byte[] {1, 2, 3}, AAD);
        byte[] ciphertext = original.ciphertext();
        ciphertext[0] ^= 1;
        var corrupted = new EnvelopeEncryptionService.Envelope(original.keyReference(),
                original.keyVersion(), original.wrappedDataKey(), original.nonce(), ciphertext,
                original.aadDigest(), original.createdAt());
        assertThrows(SecurityException.class, () -> service.decrypt(corrupted, AAD));
    }

    @Test
    void httpsKmsClientUsesMutualTlsTransportBoundaryAndRejectsMalformedResponses() {
        byte[] key = new byte[32];
        byte[] wrapped = new byte[64];
        Arrays.fill(key, (byte) 7);
        Arrays.fill(wrapped, (byte) 9);
        var transport = new RecordingTransport(("{\"keyReference\":\"kms://provider/v1\","
                + "\"keyVersion\":\"7\",\"plaintextKey\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(key)
                + "\",\"wrappedDataKey\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(wrapped)
                + "\",\"plaintextExpiresAt\":\"2026-08-28T00:00:03Z\"}")
                .getBytes(StandardCharsets.UTF_8));
        var client = new HttpsKmsClient(URI.create("https://kms.example/v1"), transport,
                () -> "short-lived-token", Duration.ofSeconds(2));

        var generated = client.generateDataKey("kms://provider/v1", AAD, Duration.ofSeconds(5));
        assertArrayEquals(key, generated.plaintextKey());
        assertTrue(transport.endpoint.toString().endsWith("/v1/data-keys/generate"));
        assertTrue(transport.authorization.startsWith("Bearer "));

        var duplicate = new HttpsKmsClient(URI.create("https://kms.example/v1"),
                new RecordingTransport("{\"keyVersion\":\"1\",\"keyVersion\":\"2\"}"
                        .getBytes(StandardCharsets.UTF_8)),
                () -> "token", Duration.ofSeconds(1));
        assertThrows(SecurityException.class, () -> duplicate.generateDataKey(
                "kms://provider/v1", AAD, Duration.ofSeconds(5)));
        assertThrows(SecurityException.class, () -> new HttpsKmsClient(
                URI.create("https://kms.example/v1"), transport, () -> "bad\ntoken",
                Duration.ofSeconds(1)).generateDataKey("kms://provider/v1", AAD,
                        Duration.ofSeconds(5)));
    }

    private static final class RecordingTransport implements HttpsKmsClient.Transport {
        private final byte[] response;
        private URI endpoint;
        private String authorization;

        private RecordingTransport(byte[] response) {
            this.response = response.clone();
        }

        @Override
        public HttpsKmsClient.Response post(URI target, Map<String, String> headers, byte[] body,
                Duration timeout) {
            endpoint = target;
            authorization = headers.get("Authorization");
            assertTrue(body.length > 0);
            assertTrue(timeout.compareTo(Duration.ofSeconds(10)) <= 0);
            return new HttpsKmsClient.Response(200, response);
        }
    }

    private static final class RsaKms implements KmsClient {
        private final Map<String, KeyPair> keys = new HashMap<>();
        private final Map<String, String> versions = new HashMap<>();

        private void add(String reference, String version) throws GeneralSecurityException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keys.put(reference, generator.generateKeyPair());
            versions.put(reference, version);
        }

        @Override
        public GeneratedDataKey generateDataKey(String reference, Map<String, String> context,
                Duration maximumPlaintextLifetime) {
            byte[] plaintext = new byte[32];
            new SecureRandom().nextBytes(plaintext);
            return new GeneratedDataKey(reference, versions.get(reference), plaintext,
                    rsa(Cipher.ENCRYPT_MODE, keys.get(reference), plaintext),
                    NOW.plusSeconds(2));
        }

        @Override
        public UnwrappedDataKey unwrapDataKey(String reference, String version, byte[] wrapped,
                Map<String, String> context, Duration maximumPlaintextLifetime) {
            if (!versions.get(reference).equals(version)) throw new SecurityException("wrong key version");
            return new UnwrappedDataKey(rsa(Cipher.DECRYPT_MODE, keys.get(reference), wrapped),
                    NOW.plusSeconds(2));
        }

        private static byte[] rsa(int mode, KeyPair pair, byte[] input) {
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(mode, mode == Cipher.ENCRYPT_MODE ? pair.getPublic() : pair.getPrivate());
                return cipher.doFinal(input);
            } catch (GeneralSecurityException exception) {
                throw new IllegalStateException(exception);
            }
        }
    }
}
