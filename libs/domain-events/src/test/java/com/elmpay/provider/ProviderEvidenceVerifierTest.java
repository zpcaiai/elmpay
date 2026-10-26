package com.elmpay.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
