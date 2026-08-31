package com.elmpay.payment.billing;

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
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BillingLifecycleTest {
    private static final String RENEWAL_RESULT = "PROVIDER_RENEWAL_RESULT";
    private static final String DUNNING_RESULT = "PROVIDER_DUNNING_RESULT";

    @Test void mandateRejectsPanAndEnforcesScope() {
        var mandates = new MandateService(Clock.systemUTC());
        assertThrows(SecurityException.class, () -> mandates.create("t", "c", "psp", "m",
                "4111111111111111", "renewal", 100, "USD", "digest"));
        var mandate = mandates.create("t", "c", "psp", "m", "pm_tok_opaque",
                "renewal", 100, "USD", "digest");
        mandates.authorize("t", mandate.id(), "renewal", 100, "USD");
        assertThrows(SecurityException.class,
                () -> mandates.authorize("t", mandate.id(), "other", 1, "USD"));
        mandates.revoke("t", mandate.id());
        assertThrows(SecurityException.class,
                () -> mandates.authorize("t", mandate.id(), "renewal", 1, "USD"));
    }

    @Test void prorationUsesHalfEvenIntegerArithmetic() {
        var adjustment = new ProrationCalculator().calculate(1001, 2001, 1, 2);
        assertEquals(500, adjustment.oldUnusedCreditMinor());
        assertEquals(1000, adjustment.newRemainingChargeMinor());
        assertEquals(500, adjustment.netDebitMinor());
    }

    @Test void usageIsIdempotentAndRenewalRequiresBoundProviderEvidence() throws Exception {
        Instant now = Instant.parse("2026-08-26T00:00:00Z");
        var service = new SubscriptionService(Clock.fixed(now, ZoneOffset.UTC));
        service.addPlan(new SubscriptionService.Plan("plan", "t", 100, "USD",
                Duration.ofDays(30), Duration.ZERO, true));
        var subscription = service.subscribe("t", "c", "plan", "m");
        service.recordUsage("t", subscription.id(), "u1", 4);
        service.recordUsage("t", subscription.id(), "u1", 4);
        assertEquals(4, service.get("t", subscription.id()).usage());

        EvidenceFixture fixture = new EvidenceFixture(now, Set.of(RENEWAL_RESULT));
        String unknownDigest = "a".repeat(64);
        Map<String, String> unknownFields = subscriptionFields(subscription.id(), "unknown",
                unknownDigest);
        VerifiedProviderEvidence unknown = fixture.verify(RENEWAL_RESULT, unknownFields);
        var before = service.get("t", subscription.id());
        assertEquals(before, service.renewalResult("t", subscription.id(),
                SubscriptionService.ProviderResult.UNKNOWN, "stripe", unknownDigest, unknown));

        assertThrows(SecurityException.class, () -> service.renewalResult("t",
                subscription.id(), SubscriptionService.ProviderResult.UNKNOWN, "stripe",
                unknownDigest, null));
        assertThrows(SecurityException.class, () -> service.renewalResult("t",
                subscription.id(), SubscriptionService.ProviderResult.FAILED, "stripe",
                unknownDigest, unknown));

        String successDigest = "b".repeat(64);
        VerifiedProviderEvidence succeeded = fixture.verify(RENEWAL_RESULT,
                subscriptionFields(subscription.id(), "succeeded", successDigest));
        var renewed = service.renewalResult("t", subscription.id(),
                SubscriptionService.ProviderResult.SUCCEEDED, "stripe", successDigest,
                succeeded);
        assertEquals(SubscriptionService.Status.ACTIVE, renewed.status());
        assertEquals(before.periodEnd(), renewed.periodStart());
        assertEquals(0, renewed.usage());
    }

    @Test void dunningUnknownWaitsAndQueryResultRequiresExactEvidence() throws Exception {
        Instant now = Instant.parse("2026-08-26T00:00:00Z");
        var service = new DunningService(Clock.fixed(now, ZoneOffset.UTC),
                new DunningService.Policy(List.of(Duration.ofSeconds(1),
                        Duration.ofSeconds(2)), Duration.ofDays(1)));
        var value = service.open("t", "s");
        EvidenceFixture fixture = new EvidenceFixture(now, Set.of(DUNNING_RESULT));
        String unknownDigest = "c".repeat(64);
        VerifiedProviderEvidence unknownAttempt = fixture.verify(DUNNING_RESULT,
                dunningFields(value.id(), "s", 1, "unknown", unknownDigest));

        String caseId = value.id();
        assertThrows(SecurityException.class, () -> service.recordAttempt("t", caseId,
                DunningService.ProviderResult.UNKNOWN, "stripe", unknownDigest, null));
        assertEquals(0, service.get("t", caseId).attempts());

        value = service.recordAttempt("t", caseId, DunningService.ProviderResult.UNKNOWN,
                "stripe", unknownDigest, unknownAttempt);
        assertEquals(DunningService.Status.WAITING_PROVIDER_QUERY, value.status());
        assertEquals(1, value.attempts());

        String queryUnknownDigest = "d".repeat(64);
        VerifiedProviderEvidence queryUnknown = fixture.verify(DUNNING_RESULT,
                dunningFields(caseId, "s", 1, "unknown", queryUnknownDigest));
        assertEquals(value, service.resumeAfterQuery("t", caseId,
                DunningService.ProviderResult.UNKNOWN, "stripe", queryUnknownDigest,
                queryUnknown));

        String failureDigest = "e".repeat(64);
        VerifiedProviderEvidence wrongEntity = fixture.verify(DUNNING_RESULT,
                dunningFields("other-case", "s", 1, "failed", failureDigest));
        assertThrows(SecurityException.class, () -> service.resumeAfterQuery("t", caseId,
                DunningService.ProviderResult.FAILED, "stripe", failureDigest, wrongEntity));
        assertThrows(SecurityException.class, () -> service.resumeAfterQuery("t", caseId,
                DunningService.ProviderResult.FAILED, "stripe", failureDigest, null));

        VerifiedProviderEvidence failed = fixture.verify(DUNNING_RESULT,
                dunningFields(caseId, "s", 1, "failed", failureDigest));
        value = service.resumeAfterQuery("t", caseId, DunningService.ProviderResult.FAILED,
                "stripe", failureDigest, failed);
        assertEquals(DunningService.Status.SCHEDULED, value.status());
        assertEquals(1, value.attempts());
    }

    private static Map<String, String> subscriptionFields(String subscriptionId, String result,
            String digest) {
        return Map.of("tenantId", "t", "provider", "stripe", "entityId", subscriptionId,
                "result", result, "providerResultDigest", digest);
    }

    private static Map<String, String> dunningFields(String caseId, String subscriptionId,
            int attempt, String result, String digest) {
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        fields.put("tenantId", "t");
        fields.put("provider", "stripe");
        fields.put("entityId", caseId);
        fields.put("subscriptionId", subscriptionId);
        fields.put("attempt", Integer.toString(attempt));
        fields.put("result", result);
        fields.put("providerResultDigest", digest);
        return Map.copyOf(fields);
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
            ProviderEvidenceReceipt unsigned = new ProviderEvidenceReceipt(type, fields,
                    "stripe-key-1", now.minusSeconds(10), now.plusSeconds(120),
                    "provider-evidence-nonce-" + String.format("%08d", ++nonce),
                    new byte[64]);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(ProviderEvidenceVerifier.signaturePayload(unsigned));
            ProviderEvidenceReceipt signed = new ProviderEvidenceReceipt(type, fields,
                    unsigned.keyId(), unsigned.issuedAt(), unsigned.expiresAt(), unsigned.nonce(),
                    signer.sign());
            return verifier.verify(signed, type, fields, now);
        }
    }
}
