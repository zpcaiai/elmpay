package com.elmpay.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Modifier;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

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
        assertEquals("decision/kyb-001", verified.decisionReference());
        assertEquals(DIGEST, verified.payloadDigest());
        assertTrue(verified.receiptDigest().matches("[0-9a-f]{64}"));
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
