package com.elmpay.tenant;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Modifier;
import java.security.DigestException;
import java.security.GeneralSecurityException;
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
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

@Isolated("temporarily removes JCA providers to verify fail-closed behavior")
final class TenantEvidenceVerifierTest {
    private static final UUID TENANT_A =
            UUID.fromString("24000000-0000-0000-0000-000000000001");
    private static final UUID TENANT_B =
            UUID.fromString("24000000-0000-0000-0000-000000000099");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String DIGEST = "a".repeat(64);
    private static final String KEY_ID = "tenant-authority-key-1";
    private static final String AUTHORITY = "licensed-tenant-authority";

    @Test
    void validReceiptCreatesOnlyOpaqueExactlyBoundEvidence() {
        Fixture fixture = new Fixture();
        AuthorityEvidenceReceipt receipt = fixture.signed(TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, AUTHORITY, "decision/kyb-001", DIGEST,
                NOW.minusSeconds(1), NOW.plusSeconds(120), "tenant-evidence-nonce-0001");

        VerifiedTenantEvidence verified = fixture.verifier.verify(receipt, TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, NOW);

        assertEquals(TENANT_A, verified.tenantId());
        assertEquals(TenantEvidenceType.KYB_VERIFIED, verified.evidenceType());
        assertEquals(AUTHORITY, verified.authority());
        assertEquals("decision/kyb-001", verified.decisionReference());
        assertEquals(DIGEST, verified.payloadDigest());
        assertTrue(verified.receiptDigest().matches("[0-9a-f]{64}"));
        assertEquals("tenant-authority-workload", verified.signerIdentity());
        assertEquals(KEY_ID, verified.keyId());
        assertEquals(NOW.minusSeconds(1), verified.issuedAt());
        assertEquals(NOW.plusSeconds(120), verified.expiresAt());
        assertFalse(Arrays.stream(VerifiedTenantEvidence.class.getDeclaredConstructors())
                .anyMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
    }

    @Test
    void tenantTypeAuthoritySignatureAndPayloadTamperingFailClosed() {
        Fixture fixture = new Fixture();
        AuthorityEvidenceReceipt valid = fixture.signed(TENANT_A,
                TenantEvidenceType.CONTRACT_SIGNED, AUTHORITY, "decision/contract-001", DIGEST,
                NOW.minusSeconds(1), NOW.plusSeconds(120), "tenant-evidence-nonce-0002");
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(valid, TENANT_B,
                TenantEvidenceType.CONTRACT_SIGNED, NOW));
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(valid, TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, NOW));
        AuthorityEvidenceReceipt unknownKey = new AuthorityEvidenceReceipt(valid.tenantId(),
                valid.evidenceType(), valid.authority(), valid.decisionReference(),
                valid.payloadDigest(), valid.issuedAt(), valid.expiresAt(),
                "tenant-evidence-nonce-unknown", "unknown-tenant-key", valid.signature());
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(unknownKey, TENANT_A,
                TenantEvidenceType.CONTRACT_SIGNED, NOW));

        AuthorityEvidenceReceipt wrongAuthority = fixture.signed(TENANT_A,
                TenantEvidenceType.CONTRACT_SIGNED, "untrusted-tenant-authority",
                "decision/contract-002", DIGEST, NOW.minusSeconds(1), NOW.plusSeconds(120),
                "tenant-evidence-nonce-0003");
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(wrongAuthority,
                TENANT_A, TenantEvidenceType.CONTRACT_SIGNED, NOW));

        AuthorityEvidenceReceipt tampered = new AuthorityEvidenceReceipt(valid.tenantId(),
                valid.evidenceType(), valid.authority(), "decision/contract-tampered",
                "b".repeat(64), valid.issuedAt(), valid.expiresAt(),
                "tenant-evidence-nonce-0004", valid.keyId(), valid.signature());
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(tampered, TENANT_A,
                TenantEvidenceType.CONTRACT_SIGNED, NOW));
    }

    @Test
    void expiredFutureUnknownAndMutatedNonceEvidenceAreRejected() {
        Fixture fixture = new Fixture();
        AuthorityEvidenceReceipt expired = fixture.signed(TENANT_A,
                TenantEvidenceType.SETTLEMENT_COMPLETE, AUTHORITY, "decision/settlement-old",
                DIGEST, NOW.minusSeconds(120), NOW, "tenant-evidence-nonce-0005");
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(expired, TENANT_A,
                TenantEvidenceType.SETTLEMENT_COMPLETE, NOW));

        AuthorityEvidenceReceipt future = fixture.signed(TENANT_A,
                TenantEvidenceType.SETTLEMENT_COMPLETE, AUTHORITY,
                "decision/settlement-future", DIGEST, NOW.plusSeconds(30),
                NOW.plusSeconds(90), "tenant-evidence-nonce-0006");
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(future, TENANT_A,
                TenantEvidenceType.SETTLEMENT_COMPLETE, NOW));
        assertThrows(IllegalArgumentException.class, () -> new AuthorityEvidenceReceipt(TENANT_A,
                TenantEvidenceType.UNKNOWN, AUTHORITY, "decision/unknown-001", DIGEST,
                NOW.minusSeconds(1), NOW.plusSeconds(30), "tenant-evidence-nonce-0007", KEY_ID,
                new byte[64]));

        AuthorityEvidenceReceipt first = fixture.signed(TENANT_A,
                TenantEvidenceType.KEK_DESTROYED, AUTHORITY, "decision/kek-001", DIGEST,
                NOW.minusSeconds(1), NOW.plusSeconds(120), "shared-tenant-nonce-00001");
        String firstDigest = fixture.verifier.verify(first, TENANT_A,
                TenantEvidenceType.KEK_DESTROYED, NOW).receiptDigest();
        assertEquals(firstDigest, fixture.verifier.verify(first, TENANT_A,
                TenantEvidenceType.KEK_DESTROYED, NOW).receiptDigest());
        AuthorityEvidenceReceipt mutated = fixture.signed(TENANT_B,
                TenantEvidenceType.KEK_DESTROYED, AUTHORITY, "decision/kek-002",
                "b".repeat(64), NOW.minusSeconds(1), NOW.plusSeconds(120),
                "shared-tenant-nonce-00001");
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(mutated, TENANT_B,
                TenantEvidenceType.KEK_DESTROYED, NOW));
    }

    @Test
    void rejectsInvalidVerifierPolicyTrustKeysRevocationAndKeyWindows() throws Exception {
        Fixture fixture = new Fixture();
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier(Map.of(),
                (receipt, digest, acceptedAt) -> true, Duration.ofMinutes(5), Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier(
                Map.of(KEY_ID, fixture.trustKey(Set.of(TenantEvidenceType.KYB_VERIFIED), false)),
                (receipt, digest, acceptedAt) -> true, Duration.ZERO, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier(
                Map.of(KEY_ID, fixture.trustKey(Set.of(TenantEvidenceType.KYB_VERIFIED), false)),
                (receipt, digest, acceptedAt) -> true, Duration.ofMinutes(11), Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier(
                Map.of(KEY_ID, fixture.trustKey(Set.of(TenantEvidenceType.KYB_VERIFIED), false)),
                (receipt, digest, acceptedAt) -> true, Duration.ofMinutes(5),
                Duration.ofSeconds(121)));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier.TrustKey(
                fixture.keyPair.getPublic(), "tenant-authority-workload", AUTHORITY, Set.of(),
                NOW.minusSeconds(60), NOW.plusSeconds(60), false));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier.TrustKey(
                fixture.keyPair.getPublic(), "tenant-authority-workload", AUTHORITY,
                Set.of(TenantEvidenceType.UNKNOWN), NOW.minusSeconds(60), NOW.plusSeconds(60),
                false));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier.TrustKey(
                fixture.keyPair.getPublic(), " ", AUTHORITY,
                Set.of(TenantEvidenceType.KYB_VERIFIED), NOW.minusSeconds(60),
                NOW.plusSeconds(60), false));
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier.TrustKey(
                rsa.getPublic(), "tenant-authority-workload", AUTHORITY,
                Set.of(TenantEvidenceType.KYB_VERIFIED), NOW.minusSeconds(60),
                NOW.plusSeconds(60), false));

        Map<String, TenantEvidenceVerifier.TrustKey> malformedKeys = new HashMap<>();
        malformedKeys.put("invalid key id", fixture.trustKey(
                Set.of(TenantEvidenceType.KYB_VERIFIED), false));
        assertThrows(IllegalArgumentException.class, () -> new TenantEvidenceVerifier(
                malformedKeys, (receipt, digest, acceptedAt) -> true,
                Duration.ofMinutes(5), Duration.ZERO));

        AuthorityEvidenceReceipt receipt = fixture.signed(TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, AUTHORITY, "decision/kyb-002", DIGEST,
                NOW.minusSeconds(1), NOW.plusSeconds(120), "tenant-evidence-nonce-0010");
        TenantEvidenceVerifier revokedVerifier = verifier(fixture.trustKey(
                Set.of(TenantEvidenceType.KYB_VERIFIED), true));
        assertThrows(SecurityException.class, () -> revokedVerifier.verify(receipt, TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, NOW));
        TenantEvidenceVerifier otherTypeVerifier = verifier(fixture.trustKey(
                Set.of(TenantEvidenceType.CONTRACT_SIGNED), false));
        assertThrows(SecurityException.class, () -> otherTypeVerifier.verify(receipt, TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, NOW));
        TenantEvidenceVerifier expiredKeyVerifier = verifier(new TenantEvidenceVerifier.TrustKey(
                fixture.keyPair.getPublic(), "tenant-authority-workload", AUTHORITY,
                Set.of(TenantEvidenceType.KYB_VERIFIED), NOW.minusSeconds(120), NOW, false));
        assertThrows(SecurityException.class, () -> expiredKeyVerifier.verify(receipt, TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, NOW));
    }

    @Test
    void unavailableEd25519ProviderFailsClosedAndIsRestored() {
        Fixture fixture = new Fixture();
        AuthorityEvidenceReceipt signed = fixture.signed(TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, AUTHORITY, "decision/kyb-provider-unavailable",
                DIGEST, NOW.minusSeconds(1), NOW.plusSeconds(120),
                "tenant-evidence-provider-unavailable");

        withoutProviders("Signature", "Ed25519", () -> {
            SecurityException failure = assertThrows(SecurityException.class,
                    () -> fixture.verifier.verify(signed, TENANT_A,
                            TenantEvidenceType.KYB_VERIFIED, NOW));
            assertInstanceOf(NoSuchAlgorithmException.class, failure.getCause());
        });
    }

    @Test
    void unavailableSha256ProviderFailsClosedAndIsRestored() {
        Fixture fixture = new Fixture();
        AuthorityEvidenceReceipt signed = fixture.signed(TENANT_A,
                TenantEvidenceType.KYB_VERIFIED, AUTHORITY, "decision/kyb-sha-unavailable",
                DIGEST, NOW.minusSeconds(1), NOW.plusSeconds(120),
                "tenant-evidence-sha-unavailable");

        withoutProviders("MessageDigest", "SHA-256", () -> {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> fixture.verifier.verify(signed, TENANT_A,
                            TenantEvidenceType.KYB_VERIFIED, NOW));
            assertInstanceOf(NoSuchAlgorithmException.class, failure.getCause());
        });
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

    private static TenantEvidenceVerifier verifier(TenantEvidenceVerifier.TrustKey trustKey) {
        return new TenantEvidenceVerifier(Map.of(KEY_ID, trustKey),
                (receipt, digest, acceptedAt) -> true, Duration.ofMinutes(5), Duration.ZERO);
    }

    private static final class Fixture {
        private final KeyPair keyPair;
        private final TenantEvidenceVerifier verifier;

        private Fixture() {
            try {
                keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            } catch (GeneralSecurityException unavailable) {
                throw new IllegalStateException(unavailable);
            }
            Map<String, String> nonces = new HashMap<>();
            TenantEvidenceVerifier.TrustKey trust = new TenantEvidenceVerifier.TrustKey(
                    keyPair.getPublic(), "tenant-authority-workload", AUTHORITY,
                    Set.of(TenantEvidenceType.KYB_VERIFIED,
                            TenantEvidenceType.CONTRACT_SIGNED,
                            TenantEvidenceType.SETTLEMENT_COMPLETE,
                            TenantEvidenceType.RETENTION_PERIOD_STARTED,
                            TenantEvidenceType.KEK_DESTROYED), NOW.minus(Duration.ofDays(1)),
                    NOW.plus(Duration.ofDays(1)), false);
            verifier = new TenantEvidenceVerifier(Map.of(KEY_ID, trust),
                    (receipt, digest, acceptedAt) -> {
                        String existing = nonces.putIfAbsent(
                                receipt.keyId() + ":" + receipt.nonce(), digest);
                        return existing == null || existing.equals(digest);
                    }, Duration.ofMinutes(5), Duration.ofSeconds(5));
        }

        private TenantEvidenceVerifier.TrustKey trustKey(
                Set<TenantEvidenceType> evidenceTypes, boolean revoked) {
            return new TenantEvidenceVerifier.TrustKey(keyPair.getPublic(),
                    "tenant-authority-workload", AUTHORITY, evidenceTypes,
                    NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(1)), revoked);
        }

        private AuthorityEvidenceReceipt signed(UUID tenantId, TenantEvidenceType type,
                String authority, String decisionReference, String payloadDigest,
                Instant issuedAt, Instant expiresAt, String nonce) {
            AuthorityEvidenceReceipt unsigned = new AuthorityEvidenceReceipt(tenantId, type,
                    authority, decisionReference, payloadDigest, issuedAt, expiresAt, nonce,
                    KEY_ID, new byte[64]);
            try {
                Signature signer = Signature.getInstance("Ed25519");
                signer.initSign(keyPair.getPrivate());
                signer.update(TenantEvidenceVerifier.signaturePayload(unsigned));
                return new AuthorityEvidenceReceipt(tenantId, type, authority,
                        decisionReference, payloadDigest, issuedAt, expiresAt, nonce, KEY_ID,
                        signer.sign());
            } catch (GeneralSecurityException unavailable) {
                throw new IllegalStateException(unavailable);
            }
        }
    }
}
