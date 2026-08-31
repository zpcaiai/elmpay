package com.elmpay.merchant;

import com.elmpay.tenant.AuthorityEvidenceReceipt;
import com.elmpay.tenant.TenantEvidenceType;
import com.elmpay.tenant.TenantEvidenceVerifier;
import com.elmpay.tenant.VerifiedTenantEvidence;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * B24/B25/B30 application service for tenant registration, KYB metadata and onboarding.
 *
 * <p>The service owns validation and state-machine policy; the store owns atomicity, tenant RLS,
 * optimistic versions, leases and fencing. Document contents and credentials are never accepted:
 * only secret-manager or licensed-verifier references may cross this boundary.
 */
public final class MerchantControlPlane {
    private static final List<StepDefinition> ONBOARDING_STEPS = List.of(
            new StepDefinition("import_credentials", 10, true, false,
                    "credential_reference"),
            new StepDefinition("verify_domain", 20, false, false, "dns_txt_record"),
            new StepDefinition("verify_callback", 30, true, false,
                    "callback_roundtrip_id"),
            new StepDefinition("set_limits", 40, false, false, "limit_snapshot"),
            new StepDefinition("approve", 50, false, true, "approval_record"),
            new StepDefinition("go_live", 60, true, false, "binding_state"));
    private static final Set<String> ENTITY_KINDS =
            Set.of("company", "sole_trader", "individual");
    private static final Map<String, RiskLevel> CATEGORY_RISK = Map.of(
            "retail_goods", RiskLevel.LOW,
            "digital_services", RiskLevel.MEDIUM,
            "travel", RiskLevel.HIGH);
    private static final Set<String> PROHIBITED_CATEGORIES =
            Set.of("crypto_exchange", "adult_content", "unlicensed_gambling");
    private static final Map<String, Set<String>> REGION_CURRENCIES = Map.of(
            "CN", Set.of("CNY"),
            "HK", Set.of("HKD", "USD"),
            "SG", Set.of("SGD", "USD"),
            "EU", Set.of("EUR"));

    public enum TenantState {
        DRAFT,
        ACTIVE,
        SUSPENDED,
        OFFBOARDING,
        CLOSED
    }

    public enum RiskLevel {
        LOW,
        MEDIUM,
        HIGH
    }

    public enum VerificationStatus {
        PENDING,
        VERIFIED,
        REJECTED,
        EXPIRED
    }

    public enum OnboardingState {
        AWAITING_APPROVAL,
        RUNNING,
        COMPLETED,
        SUSPENDED
    }

    public record Tenant(UUID id, String externalReference, String code, TenantState state,
            long version, Instant createdAt, Instant updatedAt) {
        public Tenant {
            Objects.requireNonNull(id, "id");
            requireIdentifier(externalReference, "externalReference");
            requireCode(code, "code");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (version < 0 || updatedAt.isBefore(createdAt)) {
                throw new IllegalArgumentException("invalid tenant version or timestamps");
            }
        }
    }

    public record Project(UUID id, UUID tenantId, String code, String environment,
            boolean enabled, long version, Instant createdAt, Instant updatedAt) {
        public Project {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(tenantId, "tenantId");
            requireCode(code, "code");
            if (!List.of("test", "live").contains(environment)) {
                throw new IllegalArgumentException("environment must be test or live");
            }
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (version < 0 || updatedAt.isBefore(createdAt)) {
                throw new IllegalArgumentException("invalid project version or timestamps");
            }
        }
    }

    /** Signed authority receipts and an independent human approver for governed transitions. */
    public record TenantTransitionEvidence(List<AuthorityEvidenceReceipt> authorityReceipts,
            String secondApproverId) {
        public TenantTransitionEvidence {
            authorityReceipts = List.copyOf(Objects.requireNonNull(authorityReceipts,
                    "authorityReceipts"));
            if (authorityReceipts.size() > 5
                    || authorityReceipts.stream().anyMatch(Objects::isNull)
                    || authorityReceipts.size() != authorityReceipts.stream()
                            .map(AuthorityEvidenceReceipt::evidenceType).distinct().count()
                    || authorityReceipts.size() != authorityReceipts.stream()
                            .map(receipt -> receipt.keyId() + "\u0000" + receipt.nonce())
                            .distinct().count()) {
                throw new IllegalArgumentException(
                        "tenant transition receipts must be bounded and type-unique");
            }
            if (secondApproverId != null) {
                requireIdentifier(secondApproverId, "secondApproverId");
            }
        }

        public static TenantTransitionEvidence none() {
            return new TenantTransitionEvidence(List.of(), null);
        }
    }

    public enum QuotaKind {
        PAYMENTS_PER_MINUTE(600, 60_000, false),
        API_KEYS_PER_ENVIRONMENT(10, 50, true),
        WEBHOOK_ENDPOINTS_PER_PROJECT(5, 20, false);

        private final long defaultValue;
        private final long hardCeiling;
        private final boolean environmentScoped;

        QuotaKind(long defaultValue, long hardCeiling, boolean environmentScoped) {
            this.defaultValue = defaultValue;
            this.hardCeiling = hardCeiling;
            this.environmentScoped = environmentScoped;
        }

        long defaultValue() {
            return defaultValue;
        }

        long hardCeiling() {
            return hardCeiling;
        }

        boolean environmentScoped() {
            return environmentScoped;
        }
    }

    public record ProjectQuota(UUID tenantId, UUID projectId, QuotaKind kind,
            String environment, long limitValue, long version, Instant updatedAt) {
        public ProjectQuota {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (kind.environmentScoped()) {
                if (!List.of("test", "live").contains(environment)) {
                    throw new IllegalArgumentException(
                            "environment-scoped quota requires test or live");
                }
            } else if (environment != null) {
                throw new IllegalArgumentException(
                        "project-scoped quota must not include an environment");
            }
            if (limitValue < 1 || limitValue > kind.hardCeiling() || version < 0) {
                throw new IllegalArgumentException("quota exceeds the governed hard ceiling");
            }
        }
    }

    public record MerchantProfile(UUID id, UUID tenantId, UUID projectId, UUID merchantId,
            String legalName, String entityKind, String registrationCountry,
            String operatingRegion, String settlementCurrency, String businessCategory,
            RiskLevel riskLevel, List<String> documentReferences, String profileDigest,
            VerificationStatus verificationStatus, long version, Instant createdAt,
            Instant updatedAt) {
        public MerchantProfile {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            requireText(legalName, "legalName", 1, 256);
            if (!ENTITY_KINDS.contains(entityKind)) {
                throw new IllegalArgumentException("unsupported merchant entity kind");
            }
            requireCountry(registrationCountry);
            if (!REGION_CURRENCIES.containsKey(operatingRegion)) {
                throw new IllegalArgumentException("unsupported operating region");
            }
            if (!REGION_CURRENCIES.get(operatingRegion).contains(settlementCurrency)) {
                throw new IllegalArgumentException("settlement currency is invalid for region");
            }
            if ("CN".equals(operatingRegion) && !"CN".equals(registrationCountry)) {
                throw new IllegalArgumentException("CN operations require a local entity");
            }
            if (PROHIBITED_CATEGORIES.contains(businessCategory)) {
                throw new IllegalArgumentException("prohibited business category");
            }
            RiskLevel governedRisk = CATEGORY_RISK.get(businessCategory);
            if (governedRisk == null || governedRisk != riskLevel) {
                throw new IllegalArgumentException("category and risk level are inconsistent");
            }
            documentReferences = List.copyOf(documentReferences);
            if (documentReferences.isEmpty()) {
                throw new IllegalArgumentException("at least one KYB document reference is required");
            }
            for (String reference : documentReferences) {
                if (reference == null || (!reference.startsWith("vault://")
                        && !reference.startsWith("kyb://")) || reference.length() > 512) {
                    throw new IllegalArgumentException(
                            "KYB documents must be opaque vault:// or kyb:// references");
                }
            }
            requireDigest(profileDigest, "profileDigest");
            Objects.requireNonNull(verificationStatus, "verificationStatus");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (version < 0 || updatedAt.isBefore(createdAt)) {
                throw new IllegalArgumentException("invalid merchant profile version");
            }
        }
    }

    public record VerificationDecision(UUID id, UUID tenantId, UUID profileId,
            String profileDigest, String authority, String decisionReference,
            VerificationStatus outcome, List<String> approverIds, Instant decidedAt,
            Instant validUntil) {
        public VerificationDecision {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(profileId, "profileId");
            requireDigest(profileDigest, "profileDigest");
            requireText(authority, "authority", 2, 128);
            requireText(decisionReference, "decisionReference", 4, 256);
            if (outcome != VerificationStatus.VERIFIED
                    && outcome != VerificationStatus.REJECTED) {
                throw new IllegalArgumentException("external decision must verify or reject");
            }
            approverIds = List.copyOf(approverIds);
            if (approverIds.isEmpty() || approverIds.size() != approverIds.stream().distinct().count()) {
                throw new IllegalArgumentException("verification approvers must be non-empty and distinct");
            }
            approverIds.forEach(approver -> requireIdentifier(approver, "approverId"));
            Objects.requireNonNull(decidedAt, "decidedAt");
            Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(decidedAt)
                    || validUntil.isAfter(decidedAt.plus(Duration.ofDays(730)))) {
                throw new IllegalArgumentException("external decision validity is invalid");
            }
        }
    }

    public record Onboarding(UUID id, UUID tenantId, UUID projectId, UUID merchantId,
            UUID providerAccountId, String requestDigest, String idempotencyKey,
            String requesterId, String approverId, OnboardingState state, long version,
            Instant approvalExpiresAt, Instant createdAt, Instant updatedAt) {
        public Onboarding {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            Objects.requireNonNull(providerAccountId, "providerAccountId");
            requireDigest(requestDigest, "requestDigest");
            requireIdentifier(idempotencyKey, "idempotencyKey");
            requireIdentifier(requesterId, "requesterId");
            if (approverId != null) {
                requireIdentifier(approverId, "approverId");
                if (requesterId.equals(approverId)) {
                    throw new IllegalArgumentException("requester cannot approve their own onboarding");
                }
            }
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(approvalExpiresAt, "approvalExpiresAt");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (version < 0 || !approvalExpiresAt.isAfter(createdAt)
                    || updatedAt.isBefore(createdAt)) {
                throw new IllegalArgumentException("invalid onboarding version or timestamps");
            }
            if (state != OnboardingState.AWAITING_APPROVAL && approverId == null) {
                throw new IllegalArgumentException("approved onboarding requires an approver");
            }
        }
    }

    public record StepDefinition(String name, int order, boolean hasSideEffect,
            boolean requiresApproval, String evidenceRequired) {
        public StepDefinition {
            requireCode(name, "stepName");
            requireCode(evidenceRequired, "evidenceRequired");
            if (order < 1) {
                throw new IllegalArgumentException("step order must be positive");
            }
        }
    }

    public record StepLease(UUID tenantId, UUID onboardingId, String stepName,
            String workerId, long fencingToken, int attempt, Instant leaseUntil,
            String idempotencyKey) {
        public StepLease {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(onboardingId, "onboardingId");
            requireCode(stepName, "stepName");
            requireIdentifier(workerId, "workerId");
            requireIdentifier(idempotencyKey, "idempotencyKey");
            Objects.requireNonNull(leaseUntil, "leaseUntil");
            if (fencingToken < 1 || attempt < 1) {
                throw new IllegalArgumentException("step lease fence and attempt must be positive");
            }
        }
    }

    public interface Store {
        Tenant createTenant(Tenant tenant);

        Tenant transitionTenant(UUID tenantId, long expectedVersion, TenantState current,
                TenantState next, List<VerifiedTenantEvidence> verifiedEvidence,
                String secondApproverId, String actorId, String reason, String ticketId,
                Instant now);

        Project createProject(Project project);

        Project setProjectEnabled(UUID tenantId, UUID projectId, long expectedVersion,
                boolean enabled, String actorId, String reason, String ticketId, Instant now);

        ProjectQuota putProjectQuota(ProjectQuota quota, long expectedVersion, String actorId,
                String reason, String ticketId);

        MerchantProfile createProfile(MerchantProfile profile);

        MerchantProfile replaceProfile(MerchantProfile profile, long expectedVersion);

        MerchantProfile recordVerification(VerificationDecision decision, Instant now);

        MerchantProfile expireVerification(UUID tenantId, UUID profileId, long expectedVersion,
                Instant now);

        Onboarding createOnboarding(Onboarding onboarding, List<StepDefinition> steps);

        Onboarding approveOnboarding(UUID tenantId, UUID onboardingId, long expectedVersion,
                String requestDigest, String approverId, String reason, String ticketId,
                Instant now);

        Optional<StepLease> claimNextStep(UUID tenantId, UUID onboardingId, String workerId,
                Instant now, Duration leaseTtl);

        void completeStep(StepLease lease, String evidenceDigest, Instant now);

        void retryStep(StepLease lease, String safeErrorCode, Instant now, Duration retryDelay);
    }

    private final Store store;
    private final TenantEvidenceVerifier tenantEvidenceVerifier;
    private final Clock clock;

    public MerchantControlPlane(Store store, TenantEvidenceVerifier tenantEvidenceVerifier,
            Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.tenantEvidenceVerifier = Objects.requireNonNull(tenantEvidenceVerifier,
                "tenantEvidenceVerifier");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Tenant registerTenant(UUID tenantId, String externalReference, String code,
            Instant now) {
        Objects.requireNonNull(now, "now");
        return store.createTenant(new Tenant(tenantId, externalReference, code,
                TenantState.DRAFT, 0, now, now));
    }

    public Tenant transitionTenant(UUID tenantId, long expectedVersion, TenantState current,
            TenantState next, TenantTransitionEvidence evidence, String actorId, String reason,
            String ticketId, Instant now) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(now, "now");
        requireTenantTransition(current, next);
        requireApprovalMetadata(actorId, reason, ticketId);
        Instant transitionAt = clock.instant();
        List<VerifiedTenantEvidence> verified = verifyTransitionEvidence(tenantId, current, next,
                evidence, actorId, transitionAt);
        return store.transitionTenant(tenantId, expectedVersion, current, next, verified,
                evidence.secondApproverId(), actorId, reason, ticketId, transitionAt);
    }

    public Project registerProject(UUID projectId, UUID tenantId, String code,
            String environment, Instant now) {
        return store.createProject(new Project(projectId, tenantId, code, environment,
                false, 0, now, now));
    }

    public Project setProjectEnabled(Project project, boolean enabled, String actorId,
            String reason, String ticketId, Instant now) {
        Objects.requireNonNull(project, "project");
        requireApprovalMetadata(actorId, reason, ticketId);
        if (project.enabled() == enabled) {
            throw new IllegalArgumentException("project already has the requested state");
        }
        return store.setProjectEnabled(project.tenantId(), project.id(), project.version(),
                enabled, actorId, reason, ticketId, now);
    }

    public ProjectQuota configureProjectQuota(UUID tenantId, UUID projectId, QuotaKind kind,
            String environment, long limitValue, long expectedVersion, String actorId,
            String reason, String ticketId, Instant now) {
        requireApprovalMetadata(actorId, reason, ticketId);
        if (expectedVersion < -1) {
            throw new IllegalArgumentException("quota expectedVersion must be -1 or greater");
        }
        return store.putProjectQuota(new ProjectQuota(tenantId, projectId, kind, environment,
                limitValue, expectedVersion + 1, now), expectedVersion, actorId, reason,
                ticketId);
    }

    public MerchantProfile registerProfile(MerchantProfile profile) {
        if (profile.verificationStatus() != VerificationStatus.PENDING || profile.version() != 0) {
            throw new IllegalArgumentException("a new profile must start pending at version zero");
        }
        return store.createProfile(profile);
    }

    /** A material change invalidates the previous licensed-verifier decision. */
    public MerchantProfile replaceProfile(MerchantProfile replacement, long expectedVersion) {
        if (replacement.verificationStatus() != VerificationStatus.PENDING
                || replacement.version() != expectedVersion + 1) {
            throw new IllegalArgumentException(
                    "a replacement profile must increment version and reset verification");
        }
        return store.replaceProfile(replacement, expectedVersion);
    }

    public MerchantProfile recordExternalVerification(MerchantProfile profile,
            VerificationDecision decision, Instant now) {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(now, "now");
        if (!profile.id().equals(decision.profileId())
                || !profile.tenantId().equals(decision.tenantId())
                || !profile.profileDigest().equals(decision.profileDigest())) {
            throw new IllegalArgumentException("verification is bound to another profile");
        }
        int approversRequired = profile.riskLevel() == RiskLevel.HIGH ? 2 : 1;
        if (decision.approverIds().size() < approversRequired
                || decision.decidedAt().isAfter(now) || !decision.validUntil().isAfter(now)) {
            throw new IllegalArgumentException("verification decision is not currently valid");
        }
        return store.recordVerification(decision, now);
    }

    public MerchantProfile expireExternalVerification(MerchantProfile profile, Instant now) {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(now, "now");
        if (profile.verificationStatus() != VerificationStatus.VERIFIED) {
            throw new IllegalArgumentException("only a verified profile can expire");
        }
        return store.expireVerification(profile.tenantId(), profile.id(), profile.version(), now);
    }

    public Onboarding requestOnboarding(UUID id, UUID tenantId, UUID projectId, UUID merchantId,
            UUID providerAccountId, String requestDigest, String idempotencyKey,
            String requesterId, Instant now, Duration approvalTtl) {
        requirePositive(approvalTtl, "approvalTtl");
        if (approvalTtl.compareTo(Duration.ofHours(72)) > 0) {
            throw new IllegalArgumentException("approvalTtl must not exceed 72 hours");
        }
        Onboarding onboarding = new Onboarding(id, tenantId, projectId, merchantId,
                providerAccountId, requestDigest, idempotencyKey, requesterId, null,
                OnboardingState.AWAITING_APPROVAL, 0, now.plus(approvalTtl), now, now);
        return store.createOnboarding(onboarding, ONBOARDING_STEPS);
    }

    public Onboarding approveOnboarding(Onboarding onboarding, String requestDigest,
            String approverId, String reason, String ticketId, Instant now) {
        Objects.requireNonNull(onboarding, "onboarding");
        requireDigest(requestDigest, "requestDigest");
        requireApprovalMetadata(approverId, reason, ticketId);
        if (onboarding.state() != OnboardingState.AWAITING_APPROVAL
                || !onboarding.requestDigest().equals(requestDigest)
                || onboarding.requesterId().equals(approverId)
                || !onboarding.approvalExpiresAt().isAfter(now)) {
            throw new IllegalArgumentException(
                    "onboarding approval is stale, self-approved or bound to another digest");
        }
        return store.approveOnboarding(onboarding.tenantId(), onboarding.id(),
                onboarding.version(), requestDigest, approverId, reason, ticketId, now);
    }

    public Optional<StepLease> claimNextStep(UUID tenantId, UUID onboardingId, String workerId,
            Instant now, Duration leaseTtl) {
        requirePositive(leaseTtl, "leaseTtl");
        return store.claimNextStep(tenantId, onboardingId, workerId, now, leaseTtl);
    }

    public void completeStep(StepLease lease, String evidenceDigest, Instant now) {
        requireDigest(evidenceDigest, "evidenceDigest");
        store.completeStep(lease, evidenceDigest, now);
    }

    public void retryStep(StepLease lease, String safeErrorCode, Instant now,
            Duration retryDelay) {
        if (safeErrorCode == null || !safeErrorCode.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("safeErrorCode has an invalid format");
        }
        requirePositive(retryDelay, "retryDelay");
        store.retryStep(lease, safeErrorCode, now, retryDelay);
    }

    static void requireTenantTransition(TenantState current, TenantState next) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(next, "next");
        boolean allowed = switch (current) {
            case DRAFT -> next == TenantState.ACTIVE;
            case ACTIVE -> next == TenantState.SUSPENDED || next == TenantState.OFFBOARDING;
            case SUSPENDED -> next == TenantState.ACTIVE || next == TenantState.OFFBOARDING;
            case OFFBOARDING -> next == TenantState.CLOSED;
            case CLOSED -> false;
        };
        if (!allowed) {
            throw new IllegalArgumentException(
                    "tenant transition is not allowed: " + current + " -> " + next);
        }
    }

    static List<StepDefinition> onboardingSteps() {
        return ONBOARDING_STEPS;
    }

    private List<VerifiedTenantEvidence> verifyTransitionEvidence(UUID tenantId,
            TenantState current, TenantState next, TenantTransitionEvidence evidence,
            String actorId, Instant verifiedAt) {
        Objects.requireNonNull(evidence, "evidence");
        boolean fourEyes = (current == TenantState.SUSPENDED && next == TenantState.ACTIVE)
                || next == TenantState.OFFBOARDING;
        if (fourEyes && (evidence.secondApproverId() == null
                || evidence.secondApproverId().equals(actorId))) {
            throw new IllegalArgumentException("transition requires a distinct second approver");
        }
        Set<TenantEvidenceType> required;
        if (current == TenantState.DRAFT && next == TenantState.ACTIVE) {
            required = Set.of(TenantEvidenceType.KYB_VERIFIED,
                    TenantEvidenceType.CONTRACT_SIGNED);
        } else if (current == TenantState.OFFBOARDING && next == TenantState.CLOSED) {
            required = Set.of(TenantEvidenceType.SETTLEMENT_COMPLETE,
                    TenantEvidenceType.RETENTION_PERIOD_STARTED,
                    TenantEvidenceType.KEK_DESTROYED);
        } else {
            required = Set.of();
        }
        Set<TenantEvidenceType> submitted = evidence.authorityReceipts().stream()
                .map(AuthorityEvidenceReceipt::evidenceType)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (!required.equals(submitted)) {
            throw new IllegalArgumentException(
                    "tenant transition requires the exact governed authority evidence set");
        }
        return evidence.authorityReceipts().stream()
                .map(receipt -> tenantEvidenceVerifier.verify(receipt, tenantId,
                        receipt.evidenceType(), verifiedAt))
                .sorted(Comparator.comparing(item -> item.evidenceType().name()))
                .toList();
    }

    private static void requireApprovalMetadata(String actorId, String reason, String ticketId) {
        requireIdentifier(actorId, "actorId");
        requireText(reason, "reason", 4, 512);
        requireIdentifier(ticketId, "ticketId");
    }

    private static void requirePositive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
    }

    private static void requireDigest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    private static void requireCountry(String value) {
        if (value == null || !value.matches("[A-Z]{2}")) {
            throw new IllegalArgumentException("registrationCountry must be ISO alpha-2");
        }
    }

    private static void requireIdentifier(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static void requireCode(String value, String field) {
        if (value == null || !value.matches("[a-z][a-z0-9_-]{1,63}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }

    private static void requireText(String value, String field, int minimum, int maximum) {
        if (value == null || value.length() < minimum || value.length() > maximum
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }
}
