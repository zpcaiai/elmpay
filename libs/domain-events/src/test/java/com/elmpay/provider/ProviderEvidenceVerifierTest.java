package com.elmpay.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.DigestException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

@Isolated("temporarily removes JCA providers to verify fail-closed behavior")
final class ProviderEvidenceVerifierTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String TYPE = "PROVIDER_RENEWAL_RESULT";
    private KeyPair keyPair;
    private Map<String, String> nonces;
    private ProviderEvidenceVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        nonces = new HashMap<>();
        ProviderEvidenceVerifier.TrustKey key = new ProviderEvidenceVerifier.TrustKey(
                keyPair.getPublic(), "stripe-query-verifier", "stripe", Set.of(TYPE),
                NOW.minusSeconds(60), NOW.plusSeconds(3_600), false);
        verifier = new ProviderEvidenceVerifier(Map.of("stripe-key-1", key),
                (receipt, digest, acceptedAt) -> {
                    String prior = nonces.putIfAbsent(receipt.keyId() + ":" + receipt.nonce(),
                            digest);
                    return prior == null || prior.equals(digest);
                }, Duration.ofMinutes(5), Duration.ZERO);
    }

    @Test
    void verifiesExactReceiptAndAllowsOnlyIdenticalReplay() throws Exception {
        Map<String, String> fields = fields("succeeded");
        ProviderEvidenceReceipt receipt = receipt(fields, "provider-evidence-nonce-0001");
        VerifiedProviderEvidence verified = verifier.verify(receipt, TYPE, fields, NOW);
        assertEquals(TYPE, verified.evidenceType());
        assertEquals(fields, verified.fields());
        assertEquals("stripe-query-verifier", verified.signerIdentity());
        assertEquals(64, verified.receiptDigest().length());
        assertEquals(verified.receiptDigest(),
                verifier.verify(receipt, TYPE, fields, NOW).receiptDigest());

        ProviderEvidenceReceipt mutation = receipt(fields("failed"),
                "provider-evidence-nonce-0001");
        assertThrows(SecurityException.class, () ->
                verifier.verify(mutation, TYPE, fields("failed"), NOW));
    }

    @Test
    void rejectsCallerClaimsSignatureMutationAndExpiredEvidence() throws Exception {
        Map<String, String> fields = fields("succeeded");
        ProviderEvidenceReceipt valid = receipt(fields, "provider-evidence-nonce-0002");
        assertThrows(SecurityException.class, () ->
                verifier.verify(valid, TYPE, fields("failed"), NOW));

        byte[] tamperedSignature = valid.signature();
        tamperedSignature[0] ^= 1;
        ProviderEvidenceReceipt tampered = new ProviderEvidenceReceipt(
                valid.evidenceType(), valid.fields(), valid.keyId(), valid.issuedAt(),
                valid.expiresAt(), valid.nonce(), tamperedSignature);
        assertThrows(SecurityException.class, () ->
                verifier.verify(tampered, TYPE, fields, NOW));

        ProviderEvidenceReceipt expired = receipt(fields, "provider-evidence-nonce-0003",
                NOW.minusSeconds(400), NOW.minusSeconds(100));
        assertThrows(SecurityException.class, () ->
                verifier.verify(expired, TYPE, fields, NOW));
    }

    @Test
    void rejectsInvalidTrustPolicyRevokedKeysAndExcessiveEvidenceLifetime() throws Exception {
        assertThrows(IllegalArgumentException.class, () ->
                new ProviderEvidenceVerifier(Map.of(), (receipt, digest, acceptedAt) -> true,
                        Duration.ofMinutes(5), Duration.ZERO));
        ProviderEvidenceVerifier.TrustKey validTrust = new ProviderEvidenceVerifier.TrustKey(
                keyPair.getPublic(), "stripe-query-verifier", "stripe", Set.of(TYPE),
                NOW.minusSeconds(60), NOW.plusSeconds(3600), false);
        assertThrows(IllegalArgumentException.class, () ->
                new ProviderEvidenceVerifier(Map.of("stripe-key-1", validTrust),
                        (receipt, digest, acceptedAt) -> true,
                        Duration.ZERO, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () ->
                new ProviderEvidenceVerifier(Map.of("stripe-key-1", validTrust),
                        (receipt, digest, acceptedAt) -> true,
                        Duration.ofMinutes(11), Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () ->
                new ProviderEvidenceVerifier(Map.of("stripe-key-1", validTrust),
                        (receipt, digest, acceptedAt) -> true,
                        Duration.ofMinutes(5), Duration.ofSeconds(121)));
        assertThrows(IllegalArgumentException.class, () -> new ProviderEvidenceVerifier.TrustKey(
                keyPair.getPublic(), "stripe-query-verifier", "stripe", Set.of(),
                NOW.minusSeconds(60), NOW.plusSeconds(60), false));
        assertThrows(IllegalArgumentException.class, () -> new ProviderEvidenceVerifier.TrustKey(
                keyPair.getPublic(), "stripe-query-verifier", "stripe", Set.of(TYPE),
                NOW, NOW, false));
        assertThrows(IllegalArgumentException.class, () -> new ProviderEvidenceVerifier.TrustKey(
                keyPair.getPublic(), " ", "stripe", Set.of(TYPE),
                NOW.minusSeconds(60), NOW.plusSeconds(60), false));

        Map<String, String> fields = fields("succeeded");
        ProviderEvidenceVerifier revoked = verifierWithTrust(
                new ProviderEvidenceVerifier.TrustKey(keyPair.getPublic(),
                        "stripe-query-verifier", "stripe", Set.of(TYPE),
                        NOW.minusSeconds(60), NOW.plusSeconds(3600), true));
        assertThrows(SecurityException.class, () -> revoked.verify(
                receipt(fields, "provider-evidence-revoked-001"), TYPE, fields, NOW));
        ProviderEvidenceVerifier wrongType = verifierWithTrust(
                new ProviderEvidenceVerifier.TrustKey(keyPair.getPublic(),
                        "stripe-query-verifier", "stripe", Set.of("OTHER_EVIDENCE"),
                        NOW.minusSeconds(60), NOW.plusSeconds(3600), false));
        assertThrows(SecurityException.class, () -> wrongType.verify(
                receipt(fields, "provider-evidence-type-0001"), TYPE, fields, NOW));

        ProviderEvidenceReceipt longLived = receipt(fields,
                "provider-evidence-lifetime-001", NOW.minusSeconds(10), NOW.plusSeconds(400));
        assertThrows(SecurityException.class,
                () -> verifier.verify(longLived, TYPE, fields, NOW));
    }

    @Test
    void rejectsMalformedReceiptFieldsBeforeSignatureVerification() {
        Map<String, String> fields = fields("succeeded");
        assertThrows(IllegalArgumentException.class, () -> receipt("bad", fields,
                "stripe-key-1", "provider-evidence-nonce-0010", new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> receipt(TYPE, Map.of(),
                "stripe-key-1", "provider-evidence-nonce-0011", new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> receipt(TYPE,
                Map.of("bad field", "succeeded"), "stripe-key-1",
                "provider-evidence-nonce-0012", new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> receipt(TYPE, fields,
                "bad key id", "provider-evidence-nonce-0013", new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> receipt(TYPE, fields,
                "stripe-key-1", "short", new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> receipt(TYPE, fields,
                "stripe-key-1", "provider-evidence-nonce-0014", new byte[63]));
    }

    @Test
    void unavailableEd25519ProviderFailsClosedAndIsRestored() throws Exception {
        Map<String, String> fields = fields("succeeded");
        ProviderEvidenceReceipt signed = receipt(fields,
                "provider-evidence-nonce-provider-unavailable");

        withoutProviders("Signature", "Ed25519", () -> {
            SecurityException failure = assertThrows(SecurityException.class,
                    () -> verifier.verify(signed, TYPE, fields, NOW));
            assertInstanceOf(NoSuchAlgorithmException.class, failure.getCause());
        });
    }

    @Test
    void unavailableSha256ProviderFailsClosedAndIsRestored() throws Exception {
        Map<String, String> fields = fields("succeeded");
        ProviderEvidenceReceipt signed = receipt(fields,
                "provider-evidence-nonce-sha-unavailable");

        withoutProviders("MessageDigest", "SHA-256", () -> {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> verifier.verify(signed, TYPE, fields, NOW));
            assertInstanceOf(NoSuchAlgorithmException.class, failure.getCause());
        });
    }

    private static ProviderEvidenceReceipt receipt(String evidenceType,
            Map<String, String> fields, String keyId, String nonce, byte[] signature) {
        return new ProviderEvidenceReceipt(evidenceType, fields, keyId,
                NOW.minusSeconds(1), NOW.plusSeconds(120), nonce, signature);
    }

    private static void withoutProviders(String service, String algorithm, Runnable action) {
        Provider[] original = Security.getProviders();
        List<PositionedProvider> removed = new ArrayList<>();
        Provider sha512Delegate = Arrays.stream(original)
                .filter(provider -> provider.getService("MessageDigest", "SHA-512") != null)
                .findFirst().orElseThrow();
        for (int index = 0; index < original.length; index++) {
            Provider provider = original[index];
            if (provider.getService(service, algorithm) != null) {
                Security.removeProvider(provider.getName());
                removed.add(new PositionedProvider(index + 1, provider));
            }
        }
        assertTrue(!removed.isEmpty(), service + "." + algorithm + " must have a provider");
        Provider sha512Bridge = null;
        if (service.equals("MessageDigest") && algorithm.equals("SHA-256")) {
            sha512Bridge = sha512Bridge(sha512Delegate);
            Security.insertProviderAt(sha512Bridge, 1);
        }
        try {
            assertTrue(Security.getProviders(service + "." + algorithm) == null,
                    service + "." + algorithm + " should be unavailable during the probe");
            action.run();
        } finally {
            if (sha512Bridge != null) {
                Security.removeProvider(sha512Bridge.getName());
            }
            removed.sort(Comparator.comparingInt(PositionedProvider::position));
            for (PositionedProvider entry : removed) {
                Security.insertProviderAt(entry.provider(), entry.position());
            }
            String[] originalNames = Arrays.stream(original).map(Provider::getName)
                    .toArray(String[]::new);
            String[] restoredNames = Arrays.stream(Security.getProviders())
                    .map(Provider::getName).toArray(String[]::new);
            assertArrayEquals(originalNames, restoredNames);
        }
    }

    private static Provider sha512Bridge(Provider delegate) {
        return new Sha512BridgeProvider(delegate);
    }

    private static final class Sha512BridgeProvider extends Provider {
        private static final long serialVersionUID = 1L;

        private Sha512BridgeProvider(Provider delegate) {
            super("ElmpayTestSHA512Bridge", "1.0",
                    "Test-only SHA-512 bridge to isolate SHA-256 provider absence");
            putService(new Service(this, "MessageDigest", "SHA-512", "test-only",
                    List.of(), Map.of()) {
                @Override
                public Object newInstance(Object parameter) throws NoSuchAlgorithmException {
                    return new Sha512Bridge(delegate);
                }
            });
        }
    }

    private static final class Sha512Bridge extends MessageDigestSpi {
        private final MessageDigest delegate;

        private Sha512Bridge(Provider provider) throws NoSuchAlgorithmException {
            delegate = MessageDigest.getInstance("SHA-512", provider);
        }

        @Override
        protected int engineGetDigestLength() {
            return delegate.getDigestLength();
        }

        @Override
        protected void engineUpdate(byte input) {
            delegate.update(input);
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int length) {
            delegate.update(input, offset, length);
        }

        @Override
        protected byte[] engineDigest() {
            return delegate.digest();
        }

        @Override
        protected int engineDigest(byte[] output, int offset, int length) throws DigestException {
            return delegate.digest(output, offset, length);
        }

        @Override
        protected void engineReset() {
            delegate.reset();
        }
    }

    private record PositionedProvider(int position, Provider provider) { }

    private Map<String, String> fields(String result) {
        return Map.of(
                "tenantId", "11111111-1111-4111-8111-111111111111",
                "projectId", "22222222-2222-4222-8222-222222222222",
                "provider", "stripe",
                "entityId", "33333333-3333-4333-8333-333333333333",
                "billingCycleId", "33333333-3333-4333-8333-333333333333",
                "subscriptionId", "44444444-4444-4444-8444-444444444444",
                "result", result,
                "providerResultDigest", "a".repeat(64));
    }

    private ProviderEvidenceVerifier verifierWithTrust(ProviderEvidenceVerifier.TrustKey trust) {
        return new ProviderEvidenceVerifier(Map.of("stripe-key-1", trust),
                (receipt, digest, acceptedAt) -> true, Duration.ofMinutes(5), Duration.ZERO);
    }

    private ProviderEvidenceReceipt receipt(Map<String, String> fields, String nonce)
            throws Exception {
        return receipt(fields, nonce, NOW.minusSeconds(10), NOW.plusSeconds(120));
    }

    private ProviderEvidenceReceipt receipt(Map<String, String> fields, String nonce,
            Instant issuedAt, Instant expiresAt) throws Exception {
        ProviderEvidenceReceipt unsigned = new ProviderEvidenceReceipt(TYPE, fields,
                "stripe-key-1", issuedAt, expiresAt, nonce, new byte[64]);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keyPair.getPrivate());
        signer.update(ProviderEvidenceVerifier.signaturePayload(unsigned));
        return new ProviderEvidenceReceipt(TYPE, fields, "stripe-key-1", issuedAt, expiresAt,
                nonce, signer.sign());
    }
}
