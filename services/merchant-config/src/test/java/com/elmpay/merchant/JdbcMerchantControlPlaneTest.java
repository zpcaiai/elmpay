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
        String profile = resource("db/migration/V025__merchant_kyb_profile.sql");
        String onboarding = resource("db/migration/V030__merchant_onboarding_workflow.sql");
        assertTrue(registry.contains("tenant_registry_transition_guard"));
        assertTrue(registry.contains("activation requires KYB and signed contract"));
        assertTrue(registry.contains("project_quota"));
        assertTrue(registry.contains("FORCE ROW LEVEL SECURITY"));
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
