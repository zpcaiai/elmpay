package com.elmpay.payment.refund;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.provider.ProviderEvidenceReceipt;
import com.elmpay.provider.ProviderEvidenceVerifier;
import com.elmpay.provider.VerifiedProviderEvidence;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RefundServiceTest {
    private static final String DISPUTE_EVENT = "PROVIDER_DISPUTE_EVENT";
    private static final String DISPUTE_RESULT = "PROVIDER_DISPUTE_RESULT";

    @Test void reservesAmountAndRequiresFourEyes() {
        var service = new RefundService(Clock.systemUTC(),
                (capture, request) -> RefundService.RiskDecision.MANUAL_REVIEW,
                new RefundService.Provider() {
                    public RefundService.ProviderResult submit(RefundService.Refund refund) {
                        return new RefundService.ProviderResult(
                                RefundService.ProviderOutcome.SUCCEEDED, "p1");
                    }
                    public RefundService.ProviderResult query(RefundService.Refund refund) {
                        throw new AssertionError();
                    }
                });
        service.registerCapture(new RefundService.Capture("t", "pay", 1000, "USD"));
        var refund = service.request("t", "pay",
                new RefundService.Request("i1", 700, "alice", "customer request"));
        assertEquals(300, service.remainingRefundable("t", "pay"));
        assertThrows(SecurityException.class,
                () -> service.approve("t", refund.id(), "alice", "same actor"));
        assertEquals(RefundService.Status.SUCCEEDED,
                service.approve("t", refund.id(), "bob", "ticket-1").status());
        assertThrows(IllegalStateException.class, () -> service.request("t", "pay",
                new RefundService.Request("i2", 301, "carol", "too much")));
    }

    @Test void transportFailureRemainsUnknownUntilQuery() {
        var service = new RefundService(Clock.systemUTC(),
                (capture, request) -> RefundService.RiskDecision.AUTO_APPROVE,
                new RefundService.Provider() {
                    public RefundService.ProviderResult submit(RefundService.Refund refund) {
                        throw new RuntimeException("timeout");
                    }
                    public RefundService.ProviderResult query(RefundService.Refund refund) {
                        return new RefundService.ProviderResult(
                                RefundService.ProviderOutcome.SUCCEEDED, "confirmed");
                    }
                });
        service.registerCapture(new RefundService.Capture("t", "p", 100, "USD"));
        var refund = service.request("t", "p",
                new RefundService.Request("i", 100, "a", "r"));
        assertEquals(RefundService.Status.UNKNOWN, refund.status());
        assertEquals(RefundService.Status.SUCCEEDED,
                service.recoverUnknown("t", refund.id(), "worker").status());
    }

    @Test void disputesRequireCryptographicEvidenceAndExactFieldBindings() throws Exception {
        Instant now = Instant.parse("2026-08-30T00:00:00Z");
        Instant deadline = now.plusSeconds(60);
        EvidenceFixture fixture = new EvidenceFixture(now, Set.of(DISPUTE_EVENT, DISPUTE_RESULT));
        DisputeService service = new DisputeService(Clock.fixed(now, ZoneOffset.UTC));
        String eventDigest = "a".repeat(64);
        Map<String, String> eventFields = disputeEventFields(deadline, eventDigest);
        VerifiedProviderEvidence eventEvidence = fixture.verify(DISPUTE_EVENT, eventFields);

        DisputeService.ProviderEvent emptyEvidence = new DisputeService.ProviderEvent(
                "t", "stripe", "e1", "d1", "p", 100, "USD", deadline,
                eventDigest, null);
        assertThrows(SecurityException.class, () -> service.ingest(emptyEvidence));

        DisputeService.ProviderEvent event = new DisputeService.ProviderEvent(
                "t", "stripe", "e1", "d1", "p", 100, "USD", deadline,
                eventDigest, eventEvidence);
        var dispute = service.ingest(event);
        dispute = service.submitEvidence("t", dispute.providerDisputeId(), "0".repeat(64),
                "application/pdf", "alice");
        assertEquals(1, dispute.evidence().getFirst().revision());
        assertEquals(dispute, service.ingest(event));

        String unknownDigest = "b".repeat(64);
        VerifiedProviderEvidence unknown = fixture.verify(DISPUTE_RESULT,
                resultFields("d1", "unknown", unknownDigest));
        var beforeUnknown = dispute;
        assertEquals(beforeUnknown, service.resolve("t", "d1",
                DisputeService.ProviderResult.UNKNOWN, unknownDigest, unknown));

        String lostDigest = "c".repeat(64);
        VerifiedProviderEvidence lost = fixture.verify(DISPUTE_RESULT,
                resultFields("d1", "lost", lostDigest));
        assertThrows(SecurityException.class, () -> service.resolve("t", "d1",
                DisputeService.ProviderResult.LOST, "d".repeat(64), lost));
        assertThrows(SecurityException.class, () -> service.resolve("t", "d1",
                DisputeService.ProviderResult.LOST, lostDigest, null));
        assertEquals(DisputeService.Status.LOST, service.resolve("t", "d1",
                DisputeService.ProviderResult.LOST, lostDigest, lost).status());

        ProviderEvidenceReceipt signed = fixture.receipt(DISPUTE_RESULT,
                resultFields("d1", "won", "e".repeat(64)));
        byte[] tamperedSignature = signed.signature();
        tamperedSignature[0] ^= 1;
        ProviderEvidenceReceipt tampered = new ProviderEvidenceReceipt(
                signed.evidenceType(), signed.fields(), signed.keyId(), signed.issuedAt(),
                signed.expiresAt(), signed.nonce(), tamperedSignature);
        assertThrows(SecurityException.class, () -> fixture.verifier.verify(tampered,
                DISPUTE_RESULT, signed.fields(), now));
    }

    private static Map<String, String> disputeEventFields(Instant deadline, String digest) {
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        fields.put("tenantId", "t");
        fields.put("provider", "stripe");
        fields.put("entityId", "e1");
        fields.put("result", "received");
        fields.put("providerResultDigest", digest);
        fields.put("providerDisputeId", "d1");
        fields.put("paymentId", "p");
        fields.put("amountMinor", "100");
        fields.put("currency", "USD");
        fields.put("responseDeadline", deadline.toString());
        return Map.copyOf(fields);
    }

    private static Map<String, String> resultFields(String entityId, String result,
            String digest) {
        return Map.of("tenantId", "t", "provider", "stripe", "entityId", entityId,
                "result", result, "providerResultDigest", digest);
    }

    private static final class EvidenceFixture {
        private final Instant now;
        private final KeyPair keyPair;
        private final ProviderEvidenceVerifier verifier;
        private int nonce;

        private EvidenceFixture(Instant now, Set<String> evidenceTypes) throws Exception {
            this.now = now;
            keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            Map<String, String> nonces = new HashMap<>();
            ProviderEvidenceVerifier.TrustKey trustKey =
                    new ProviderEvidenceVerifier.TrustKey(keyPair.getPublic(),
                            "stripe-query-verifier", "stripe", evidenceTypes,
                            now.minusSeconds(60), now.plusSeconds(3_600), false);
            verifier = new ProviderEvidenceVerifier(Map.of("stripe-key-1", trustKey),
                    (receipt, digest, acceptedAt) -> {
                        String prior = nonces.putIfAbsent(
                                receipt.keyId() + ":" + receipt.nonce(), digest);
                        return prior == null || prior.equals(digest);
                    }, Duration.ofMinutes(5), Duration.ZERO);
        }

        private VerifiedProviderEvidence verify(String type, Map<String, String> fields)
                throws Exception {
            return verifier.verify(receipt(type, fields), type, fields, now);
        }

        private ProviderEvidenceReceipt receipt(String type, Map<String, String> fields)
                throws Exception {
            String receiptNonce = "provider-evidence-nonce-" + String.format("%08d", ++nonce);
            ProviderEvidenceReceipt unsigned = new ProviderEvidenceReceipt(type, fields,
                    "stripe-key-1", now.minusSeconds(10), now.plusSeconds(120), receiptNonce,
                    new byte[64]);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(ProviderEvidenceVerifier.signaturePayload(unsigned));
            return new ProviderEvidenceReceipt(type, fields, "stripe-key-1",
                    unsigned.issuedAt(), unsigned.expiresAt(), receiptNonce, signer.sign());
        }
    }
}
