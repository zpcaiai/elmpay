package com.elmpay.merchant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class MerchantControlPlaneTest {
    private static final UUID TENANT = UUID.fromString("24000000-0000-0000-0000-000000000001");
    private static final UUID PROJECT = UUID.fromString("24000000-0000-0000-0000-000000000002");
    private static final UUID MERCHANT = UUID.fromString("24000000-0000-0000-0000-000000000003");
    private static final UUID ACCOUNT = UUID.fromString("24000000-0000-0000-0000-000000000004");
    private static final UUID WORKFLOW = UUID.fromString("24000000-0000-0000-0000-000000000005");
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final String DIGEST = "a".repeat(64);

    @Test
    void tenantLifecycleIsExplicitAndTerminal() {
        MerchantControlPlane.requireTenantTransition(MerchantControlPlane.TenantState.DRAFT,
                MerchantControlPlane.TenantState.ACTIVE);
        MerchantControlPlane.requireTenantTransition(MerchantControlPlane.TenantState.ACTIVE,
                MerchantControlPlane.TenantState.SUSPENDED);
        assertThrows(IllegalArgumentException.class,
                () -> MerchantControlPlane.requireTenantTransition(
                        MerchantControlPlane.TenantState.CLOSED,
                        MerchantControlPlane.TenantState.ACTIVE));
        assertThrows(IllegalArgumentException.class,
                () -> MerchantControlPlane.requireTenantTransition(
                        MerchantControlPlane.TenantState.DRAFT,
                        MerchantControlPlane.TenantState.SUSPENDED));
    }

    @Test
    void tenantTransitionsRequireGovernedEvidenceAndFourEyes() {
        RecordingStore store = new RecordingStore();
        MerchantControlPlane service = new MerchantControlPlane(store);
        MerchantControlPlane.TenantTransitionEvidence none =
                MerchantControlPlane.TenantTransitionEvidence.none();
        assertThrows(IllegalArgumentException.class,
                () -> service.transitionTenant(TENANT, 0,
                        MerchantControlPlane.TenantState.DRAFT,
                        MerchantControlPlane.TenantState.ACTIVE, none, "actor-001",
                        "activate merchant", "ticket-001", NOW));
        MerchantControlPlane.Tenant activated = service.transitionTenant(TENANT, 0,
                MerchantControlPlane.TenantState.DRAFT,
                MerchantControlPlane.TenantState.ACTIVE,
                new MerchantControlPlane.TenantTransitionEvidence(true, true, false, false,
                        false, null),
                "actor-001", "activate merchant", "ticket-001", NOW);
        assertEquals(MerchantControlPlane.TenantState.ACTIVE, activated.state());

        assertThrows(IllegalArgumentException.class,
                () -> service.transitionTenant(TENANT, 1,
                        MerchantControlPlane.TenantState.ACTIVE,
                        MerchantControlPlane.TenantState.OFFBOARDING, none, "actor-001",
                        "begin offboarding", "ticket-002", NOW));
        assertThrows(IllegalArgumentException.class,
                () -> service.transitionTenant(TENANT, 2,
                        MerchantControlPlane.TenantState.OFFBOARDING,
                        MerchantControlPlane.TenantState.CLOSED, none, "actor-001",
                        "close merchant", "ticket-003", NOW));
    }

    @Test
    void kybProfileAcceptsOnlyOpaqueReferencesAndLicensedDecisionBinding() {
        MerchantControlPlane.MerchantProfile profile = profile(List.of("kyb://licensed/doc-1"));
        assertEquals(MerchantControlPlane.VerificationStatus.PENDING,
                profile.verificationStatus());
        assertThrows(IllegalArgumentException.class,
                () -> profile(List.of("/tmp/passport.pdf")));
        assertThrows(IllegalArgumentException.class,
                () -> new MerchantControlPlane.VerificationDecision(UUID.randomUUID(), TENANT,
                        profile.id(), DIGEST, "authority", "decision-1",
                        MerchantControlPlane.VerificationStatus.PENDING,
                        List.of("reviewer-001"), NOW,
                        NOW.plus(Duration.ofDays(1))));
        assertThrows(IllegalArgumentException.class,
                () -> profile("crypto_exchange", MerchantControlPlane.RiskLevel.HIGH,
                        "CN", "CNY"));
        assertThrows(IllegalArgumentException.class,
                () -> profile("digital_services", MerchantControlPlane.RiskLevel.MEDIUM,
                        "CN", "USD"));
    }

    @Test
    void highRiskVerificationRequiresTwoDistinctApproversAndCanExpire() {
        RecordingStore store = new RecordingStore();
        MerchantControlPlane service = new MerchantControlPlane(store);
        MerchantControlPlane.MerchantProfile travel = profile("travel",
                MerchantControlPlane.RiskLevel.HIGH, "HK", "USD");
        MerchantControlPlane.VerificationDecision oneReviewer =
                new MerchantControlPlane.VerificationDecision(UUID.randomUUID(), TENANT,
                        travel.id(), DIGEST, "licensed-authority", "decision-1",
                        MerchantControlPlane.VerificationStatus.VERIFIED,
                        List.of("reviewer-001"), NOW, NOW.plus(Duration.ofDays(30)));
        assertThrows(IllegalArgumentException.class,
                () -> service.recordExternalVerification(travel, oneReviewer, NOW));
        MerchantControlPlane.VerificationDecision twoReviewers =
                new MerchantControlPlane.VerificationDecision(UUID.randomUUID(), TENANT,
                        travel.id(), DIGEST, "licensed-authority", "decision-2",
                        MerchantControlPlane.VerificationStatus.VERIFIED,
                        List.of("reviewer-001", "reviewer-002"), NOW,
                        NOW.plus(Duration.ofDays(30)));
        assertEquals(MerchantControlPlane.VerificationStatus.VERIFIED,
                service.recordExternalVerification(travel, twoReviewers, NOW)
                        .verificationStatus());
    }

    @Test
    void onboardingApprovalIsFourEyesDigestBoundAndResumable() {
        RecordingStore store = new RecordingStore();
        MerchantControlPlane service = new MerchantControlPlane(store);
        MerchantControlPlane.Onboarding requested = service.requestOnboarding(WORKFLOW, TENANT,
                PROJECT, MERCHANT, ACCOUNT, DIGEST, "onboarding-key-001", "requester-001",
                NOW, Duration.ofHours(1));
        assertEquals(6, store.steps.size());
        assertEquals(MerchantControlPlane.OnboardingState.AWAITING_APPROVAL, requested.state());
        assertThrows(IllegalArgumentException.class,
                () -> service.approveOnboarding(requested, DIGEST, "requester-001",
                        "self approval", "ticket-001", NOW.plusSeconds(1)));
        assertThrows(IllegalArgumentException.class,
                () -> service.approveOnboarding(requested, "b".repeat(64), "approver-002",
                        "digest mismatch", "ticket-001", NOW.plusSeconds(1)));

        MerchantControlPlane.Onboarding approved = service.approveOnboarding(requested, DIGEST,
                "approver-002", "merchant passed independent review", "ticket-001",
                NOW.plusSeconds(1));
        assertEquals(MerchantControlPlane.OnboardingState.RUNNING, approved.state());
        Optional<MerchantControlPlane.StepLease> lease = service.claimNextStep(TENANT, WORKFLOW,
                "worker-001", NOW.plusSeconds(2), Duration.ofMinutes(1));
        assertTrue(lease.isPresent());
        assertEquals("import_credentials", lease.orElseThrow().stepName());
    }

    @Test
    void onboardingConfigurationOrdersEverySideEffect() {
        List<MerchantControlPlane.StepDefinition> steps = MerchantControlPlane.onboardingSteps();
        assertEquals(List.of(10, 20, 30, 40, 50, 60),
                steps.stream().map(MerchantControlPlane.StepDefinition::order).toList());
        assertEquals(List.of("import_credentials", "verify_domain", "verify_callback",
                "set_limits", "approve", "go_live"),
                steps.stream().map(MerchantControlPlane.StepDefinition::name).toList());
        assertEquals(List.of(true, false, true, false, false, true),
                steps.stream().map(MerchantControlPlane.StepDefinition::hasSideEffect).toList());
        assertEquals(List.of("approve"), steps.stream()
                .filter(MerchantControlPlane.StepDefinition::requiresApproval)
                .map(MerchantControlPlane.StepDefinition::name).toList());
    }

    @Test
    void onboardingApprovalCannotOutliveGovernedWindow() {
        MerchantControlPlane service = new MerchantControlPlane(new RecordingStore());
        assertThrows(IllegalArgumentException.class,
                () -> service.requestOnboarding(WORKFLOW, TENANT, PROJECT, MERCHANT, ACCOUNT,
                        DIGEST, "onboarding-key-001", "requester-001", NOW,
                        Duration.ofHours(73)));
    }

    private static MerchantControlPlane.MerchantProfile profile(List<String> references) {
        return new MerchantControlPlane.MerchantProfile(UUID.randomUUID(), TENANT, PROJECT,
                MERCHANT, "Example Merchant Ltd", "company", "CN", "CN", "CNY",
                "digital_services", MerchantControlPlane.RiskLevel.MEDIUM, references, DIGEST,
                MerchantControlPlane.VerificationStatus.PENDING, 0, NOW, NOW);
    }

    private static MerchantControlPlane.MerchantProfile profile(String category,
            MerchantControlPlane.RiskLevel risk, String region, String currency) {
        return new MerchantControlPlane.MerchantProfile(UUID.randomUUID(), TENANT, PROJECT,
                MERCHANT, "Example Merchant Ltd", "company", "CN", region, currency,
                category, risk, List.of("kyb://licensed/doc-1"), DIGEST,
                MerchantControlPlane.VerificationStatus.PENDING, 0, NOW, NOW);
    }

    private static final class RecordingStore implements MerchantControlPlane.Store {
        private List<MerchantControlPlane.StepDefinition> steps = List.of();
        private MerchantControlPlane.Onboarding onboarding;

        @Override
        public MerchantControlPlane.Tenant createTenant(MerchantControlPlane.Tenant tenant) {
            return tenant;
        }

        @Override
        public MerchantControlPlane.Tenant transitionTenant(UUID tenantId, long expectedVersion,
                MerchantControlPlane.TenantState current,
                MerchantControlPlane.TenantState next,
                MerchantControlPlane.TenantTransitionEvidence evidence, String actorId,
                String reason, String ticketId, Instant now) {
            return new MerchantControlPlane.Tenant(tenantId, "tenant-external-001",
                    "tenant_code", next, expectedVersion + 1, NOW, now);
        }

        @Override
        public MerchantControlPlane.Project createProject(MerchantControlPlane.Project project) {
            return project;
        }

        @Override
        public MerchantControlPlane.Project setProjectEnabled(UUID tenantId, UUID projectId,
                long expectedVersion, boolean enabled, String actorId, String reason,
                String ticketId, Instant now) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MerchantControlPlane.ProjectQuota putProjectQuota(
                MerchantControlPlane.ProjectQuota quota, long expectedVersion, String actorId,
                String reason, String ticketId) {
            return quota;
        }

        @Override
        public MerchantControlPlane.MerchantProfile createProfile(
                MerchantControlPlane.MerchantProfile profile) {
            return profile;
        }

        @Override
        public MerchantControlPlane.MerchantProfile replaceProfile(
                MerchantControlPlane.MerchantProfile profile, long expectedVersion) {
            return profile;
        }

        @Override
        public MerchantControlPlane.MerchantProfile recordVerification(
                MerchantControlPlane.VerificationDecision decision, Instant now) {
            MerchantControlPlane.MerchantProfile source = profile("travel",
                    MerchantControlPlane.RiskLevel.HIGH, "HK", "USD");
            return new MerchantControlPlane.MerchantProfile(decision.profileId(), TENANT,
                    PROJECT, MERCHANT, source.legalName(), source.entityKind(),
                    source.registrationCountry(), source.operatingRegion(),
                    source.settlementCurrency(), source.businessCategory(), source.riskLevel(),
                    source.documentReferences(), decision.profileDigest(), decision.outcome(), 1,
                    NOW, now);
        }

        @Override
        public MerchantControlPlane.MerchantProfile expireVerification(UUID tenantId,
                UUID profileId, long expectedVersion, Instant now) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MerchantControlPlane.Onboarding createOnboarding(
                MerchantControlPlane.Onboarding value,
                List<MerchantControlPlane.StepDefinition> definitions) {
            onboarding = value;
            steps = List.copyOf(definitions);
            return value;
        }

        @Override
        public MerchantControlPlane.Onboarding approveOnboarding(UUID tenantId,
                UUID onboardingId, long expectedVersion, String requestDigest,
                String approverId, String reason, String ticketId, Instant now) {
            onboarding = new MerchantControlPlane.Onboarding(onboarding.id(),
                    onboarding.tenantId(), onboarding.projectId(), onboarding.merchantId(),
                    onboarding.providerAccountId(), onboarding.requestDigest(),
                    onboarding.idempotencyKey(), onboarding.requesterId(), approverId,
                    MerchantControlPlane.OnboardingState.RUNNING, onboarding.version() + 1,
                    onboarding.approvalExpiresAt(), onboarding.createdAt(), now);
            return onboarding;
        }

        @Override
        public Optional<MerchantControlPlane.StepLease> claimNextStep(UUID tenantId,
                UUID onboardingId, String workerId, Instant now, Duration leaseTtl) {
            MerchantControlPlane.StepDefinition step = steps.getFirst();
            return Optional.of(new MerchantControlPlane.StepLease(tenantId, onboardingId,
                    step.name(), workerId, 1, 1, now.plus(leaseTtl),
                    onboardingId + ":" + step.name()));
        }

        @Override
        public void completeStep(MerchantControlPlane.StepLease lease, String evidenceDigest,
                Instant now) {
        }

        @Override
        public void retryStep(MerchantControlPlane.StepLease lease, String safeErrorCode,
                Instant now, Duration retryDelay) {
        }
    }
}
