package com.elmpay.merchant;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class JdbcMerchantControlPlaneTest {
    @Test
    void onboardingClaimUsesOrderedSkipLockedLeaseAndFence() {
        assertTrue(JdbcMerchantControlPlane.CLAIM_STEP_SQL.contains("FOR UPDATE OF step SKIP LOCKED"));
        assertTrue(JdbcMerchantControlPlane.CLAIM_STEP_SQL.contains("NOT EXISTS"));
        assertTrue(JdbcMerchantControlPlane.CLAIM_STEP_SQL.contains("interval '30 days'"));
        assertTrue(JdbcMerchantControlPlane.CLAIM_STEP_UPDATE_SQL.contains(
                "fencing_token = fencing_token + 1"));
        assertTrue(JdbcMerchantControlPlane.COMPLETE_STEP_SQL.contains("fencing_token = ?"));
        assertThrows(JdbcMerchantControlPlane.OptimisticConflictException.class,
                () -> JdbcMerchantControlPlane.requireOne(0,
                        "stale worker cannot complete onboarding step"));
    }

    @Test
    void onboardingCreateIsAParameterBoundIdempotentReplay() {
        assertTrue(JdbcMerchantControlPlane.CREATE_ONBOARDING_SQL.contains(
                "ON CONFLICT (tenant_id, idempotency_key) DO NOTHING"));
        assertTrue(JdbcMerchantControlPlane.CREATE_ONBOARDING_SQL.contains("request_digest"));
    }

    @Test
    void migrationsProvideRlsOptimisticLifecycleExternalDecisionAndFourEyes()
            throws IOException {
        String registry = resource("db/migration/V024__tenant_project_registry.sql");
        String authorityEvidence = resource(
                "db/migration/V101__tenant_authority_evidence.sql");
        String profile = resource("db/migration/V025__merchant_kyb_profile.sql");
        String onboarding = resource("db/migration/V030__merchant_onboarding_workflow.sql");
        assertTrue(registry.contains("tenant_registry_transition_guard"));
        assertTrue(registry.contains("activation requires KYB and signed contract"));
        assertTrue(registry.contains("project_quota"));
        assertTrue(registry.contains("FORCE ROW LEVEL SECURITY"));
        assertTrue(authorityEvidence.contains("Historical evidence_flags remain untouched"));
        assertTrue(authorityEvidence.contains("tenant_authority_evidence_nonce"));
        assertTrue(authorityEvidence.contains("merchant_tenant_authority_evidence_audit"));
        assertTrue(authorityEvidence.contains("accepted.expires_at > statement_timestamp()"));
        assertTrue(authorityEvidence.contains("FORCE ROW LEVEL SECURITY"));
        assertTrue(authorityEvidence.contains("new tenant transitions require a fresh digest-bound audit"));
        assertTrue(authorityEvidence.contains("tenant activation requires verified KYB and contract receipts"));
        assertTrue(authorityEvidence.contains("tenant transition requires a distinct second approver"));
        assertTrue(JdbcMerchantControlPlane.TRANSITION_TENANT_SQL.contains(
                "last_transition_receipt_digests"));
        assertTrue(JdbcMerchantControlPlane.INSERT_TRANSITION_EVIDENCE_AUDIT_SQL.contains(
                "decision_reference"));
        assertTrue(JdbcMerchantControlPlane.INSERT_TRANSITION_EVIDENCE_AUDIT_SQL.contains(
                "receipt_digest"));
        assertTrue(JdbcTenantEvidenceReplayGuard.INSERT_NONCE_SQL.contains(
                "ON CONFLICT (key_id,nonce) DO NOTHING"));
        assertTrue(JdbcTenantEvidenceReplayGuard.SELECT_NONCE_SQL.contains(
                "WHERE tenant_id = ?::uuid AND key_id = ? AND nonce = ?"));
        assertTrue(profile.contains("licensed-verifier decisions are immutable"));
        assertTrue(profile.contains("merchant_verification_approver_guard"));
        assertTrue(profile.contains("profile_digest"));
        assertTrue(onboarding.contains("approver_id <> requester_id"));
        assertTrue(onboarding.contains("approval_expires_at <= created_at + interval '72 hours'"));
        assertTrue(onboarding.contains("step_name = 'go_live'"));
        assertTrue(onboarding.contains("fencing_token"));
        assertTrue(onboarding.contains("merchant_onboarding_step_due_idx"));
    }

    private static String resource(String name) throws IOException {
        try (InputStream input = JdbcMerchantControlPlaneTest.class.getClassLoader()
                .getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("missing resource: " + name);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
