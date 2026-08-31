package com.elmpay.merchant;

import com.elmpay.tenant.VerifiedTenantEvidence;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL implementation of the tenant, merchant-profile and onboarding control plane. */
public final class JdbcMerchantControlPlane implements MerchantControlPlane.Store {
    static final String TRANSITION_TENANT_SQL = """
            UPDATE tenant_registry
               SET state = ?, last_transition_evidence_flags = ARRAY[]::text[],
                   last_transition_receipt_digests = ?, last_transition_audit_id = ?::uuid,
                   last_transition_actor_id = ?, last_transition_second_approver_id = ?,
                   version = version + 1, updated_at = ?::timestamptz
             WHERE id = ?::uuid AND version = ? AND state = ?
            RETURNING id, external_reference, code, state, version, created_at, updated_at
            """;
    static final String INSERT_TRANSITION_EVIDENCE_AUDIT_SQL = """
            INSERT INTO merchant_tenant_authority_evidence_audit
              (id,tenant_id,control_audit_id,evidence_type,authority,decision_reference,
               payload_digest,receipt_digest,signer_identity,key_id,issued_at,expires_at)
            VALUES (?::uuid,?::uuid,?::uuid,?,?,?,?,?,?,?,?::timestamptz,?::timestamptz)
            """;
    static final String CLAIM_STEP_SQL = """
            SELECT step.step_name, step.fencing_token
              FROM merchant_onboarding_step step
              JOIN merchant_onboarding workflow
                ON workflow.tenant_id = step.tenant_id
               AND workflow.id = step.onboarding_id
             WHERE step.tenant_id = ?::uuid AND step.onboarding_id = ?::uuid
               AND workflow.state = 'RUNNING'
               AND workflow.created_at >= (?::timestamptz - interval '30 days')
               AND step.state IN ('PENDING', 'RETRY')
               AND step.next_attempt_at <= ?::timestamptz
               AND (step.lease_until IS NULL OR step.lease_until <= ?::timestamptz)
               AND NOT EXISTS (
                   SELECT 1 FROM merchant_onboarding_step predecessor
                    WHERE predecessor.tenant_id = step.tenant_id
                      AND predecessor.onboarding_id = step.onboarding_id
                      AND predecessor.step_order < step.step_order
                      AND predecessor.state <> 'COMPLETED')
             ORDER BY step.step_order
             FOR UPDATE OF step SKIP LOCKED
            LIMIT 1
            """;
    static final String CREATE_ONBOARDING_SQL = """
            INSERT INTO merchant_onboarding
              (id, tenant_id, project_id, merchant_id, provider_account_id,
               request_digest, idempotency_key, requester_id, state, version,
               approval_expires_at, created_at, updated_at)
            VALUES (?::uuid, ?::uuid, ?::uuid, ?::uuid, ?::uuid, ?, ?, ?,
                    'AWAITING_APPROVAL', 0, ?::timestamptz, ?::timestamptz,
                    ?::timestamptz)
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
            RETURNING id, tenant_id, project_id, merchant_id,
                      provider_account_id, request_digest, idempotency_key,
                      requester_id, approver_id, state, version,
                      approval_expires_at, created_at, updated_at
            """;
    static final String CLAIM_STEP_UPDATE_SQL = """
            UPDATE merchant_onboarding_step
               SET state = 'RUNNING', lease_owner = ?, lease_until = ?::timestamptz,
                   fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
                   last_error_code = NULL, updated_at = ?::timestamptz
             WHERE tenant_id = ?::uuid AND onboarding_id = ?::uuid AND step_name = ?
               AND fencing_token = ?
            RETURNING fencing_token, attempt_count
            """;
    static final String COMPLETE_STEP_SQL = """
            UPDATE merchant_onboarding_step
               SET state = 'COMPLETED', evidence_digest = ?, lease_owner = NULL,
                   lease_until = NULL, completed_at = ?::timestamptz,
                   updated_at = ?::timestamptz
             WHERE tenant_id = ?::uuid AND onboarding_id = ?::uuid AND step_name = ?
               AND state = 'RUNNING' AND lease_owner = ? AND fencing_token = ?
               AND lease_until > ?::timestamptz
            """;

    private final DataSource dataSource;

    public JdbcMerchantControlPlane(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public MerchantControlPlane.Tenant createTenant(MerchantControlPlane.Tenant tenant) {
        Objects.requireNonNull(tenant, "tenant");
        return transaction(tenant.id(), "cannot create tenant registry entry", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tenant_registry
                      (id, external_reference, code, state, version, created_at, updated_at)
                    VALUES (?::uuid, ?, ?, ?, 0, ?::timestamptz, ?::timestamptz)
                    RETURNING id, external_reference, code, state, version, created_at, updated_at
                    """)) {
                statement.setString(1, tenant.id().toString());
                statement.setString(2, tenant.externalReference());
                statement.setString(3, tenant.code());
                statement.setString(4, tenant.state().name());
                statement.setString(5, tenant.createdAt().toString());
                statement.setString(6, tenant.updatedAt().toString());
                try (ResultSet result = statement.executeQuery()) {
                    return requiredTenant(result);
                }
            }
        });
    }

    @Override
    public MerchantControlPlane.Tenant transitionTenant(UUID tenantId, long expectedVersion,
            MerchantControlPlane.TenantState current, MerchantControlPlane.TenantState next,
            List<VerifiedTenantEvidence> verifiedEvidence, String secondApproverId,
            String actorId, String reason, String ticketId, Instant now) {
        verifiedEvidence = List.copyOf(Objects.requireNonNull(verifiedEvidence,
                "verifiedEvidence"));
        List<VerifiedTenantEvidence> receipts = verifiedEvidence;
        return transaction(tenantId, "cannot transition tenant registry entry", connection -> {
            UUID auditId = UUID.randomUUID();
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO merchant_control_audit
                      (id, tenant_id, action, target_type, target_id, actor_id, reason,
                       ticket_id, evidence_flags, second_approver_id, occurred_at)
                    VALUES (?::uuid, ?::uuid, 'TENANT_STATE_CHANGED', 'tenant', ?, ?, ?, ?,
                            ARRAY[]::text[], ?, ?::timestamptz)
                    """)) {
                statement.setString(1, auditId.toString());
                statement.setString(2, tenantId.toString());
                statement.setString(3, tenantId.toString());
                statement.setString(4, actorId);
                statement.setString(5, reason);
                statement.setString(6, ticketId);
                statement.setString(7, secondApproverId);
                statement.setString(8, now.toString());
                statement.executeUpdate();
            }
            for (VerifiedTenantEvidence receipt : receipts) {
                try (PreparedStatement statement = connection.prepareStatement(
                        INSERT_TRANSITION_EVIDENCE_AUDIT_SQL)) {
                    statement.setString(1, UUID.randomUUID().toString());
                    statement.setString(2, tenantId.toString());
                    statement.setString(3, auditId.toString());
                    statement.setString(4, receipt.evidenceType().name());
                    statement.setString(5, receipt.authority());
                    statement.setString(6, receipt.decisionReference());
                    statement.setString(7, receipt.payloadDigest());
                    statement.setString(8, receipt.receiptDigest());
                    statement.setString(9, receipt.signerIdentity());
                    statement.setString(10, receipt.keyId());
                    statement.setString(11, receipt.issuedAt().toString());
                    statement.setString(12, receipt.expiresAt().toString());
                    statement.executeUpdate();
                }
            }
            MerchantControlPlane.Tenant changed;
            try (PreparedStatement statement = connection.prepareStatement(
                    TRANSITION_TENANT_SQL)) {
                statement.setString(1, next.name());
                statement.setArray(2, stringArray(connection, receipts.stream()
                        .map(VerifiedTenantEvidence::receiptDigest).toList()));
                statement.setString(3, auditId.toString());
                statement.setString(4, actorId);
                statement.setString(5, secondApproverId);
                statement.setString(6, now.toString());
                statement.setString(7, tenantId.toString());
                statement.setLong(8, expectedVersion);
                statement.setString(9, current.name());
                try (ResultSet result = statement.executeQuery()) {
                    changed = requiredTenant(result);
                }
            }
            return changed;
        });
    }

    @Override
    public MerchantControlPlane.Project createProject(MerchantControlPlane.Project project) {
        Objects.requireNonNull(project, "project");
        return transaction(project.tenantId(), "cannot create project registry entry", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO project_registry
                      (id, tenant_id, code, environment, enabled, version, created_at, updated_at)
                    SELECT ?::uuid, ?::uuid, ?, ?, false, 0, ?::timestamptz, ?::timestamptz
                      FROM tenant_registry tenant
                     WHERE tenant.id = ?::uuid AND tenant.state IN ('DRAFT', 'ACTIVE')
                       AND (SELECT count(*) FROM project_registry existing
                             WHERE existing.tenant_id = tenant.id) < 20
                    RETURNING id, tenant_id, code, environment, enabled, version,
                              created_at, updated_at
                    """)) {
                statement.setString(1, project.id().toString());
                statement.setString(2, project.tenantId().toString());
                statement.setString(3, project.code());
                statement.setString(4, project.environment());
                statement.setString(5, project.createdAt().toString());
                statement.setString(6, project.updatedAt().toString());
                statement.setString(7, project.tenantId().toString());
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new OptimisticConflictException(
                                "tenant is absent or cannot accept projects");
                    }
                    return project(result);
                }
            }
        });
    }

    @Override
    public MerchantControlPlane.Project setProjectEnabled(UUID tenantId, UUID projectId,
            long expectedVersion, boolean enabled, String actorId, String reason,
            String ticketId, Instant now) {
        return transaction(tenantId, "cannot change project state", connection -> {
            MerchantControlPlane.Project changed;
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE project_registry project
                       SET enabled = ?, version = version + 1, updated_at = ?::timestamptz
                     WHERE project.tenant_id = ?::uuid AND project.id = ?::uuid
                       AND project.version = ? AND project.enabled <> ?
                       AND (NOT ? OR EXISTS (
                           SELECT 1 FROM tenant_registry tenant
                            WHERE tenant.id = project.tenant_id AND tenant.state = 'ACTIVE'))
                    RETURNING id, tenant_id, code, environment, enabled, version,
                              created_at, updated_at
                    """)) {
                statement.setBoolean(1, enabled);
                statement.setString(2, now.toString());
                statement.setString(3, tenantId.toString());
                statement.setString(4, projectId.toString());
                statement.setLong(5, expectedVersion);
                statement.setBoolean(6, enabled);
                statement.setBoolean(7, enabled);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new OptimisticConflictException(
                                "project state/version or active-tenant prerequisite failed");
                    }
                    changed = project(result);
                }
            }
            insertControlAudit(connection, tenantId,
                    enabled ? "PROJECT_ENABLED" : "PROJECT_DISABLED", "project", projectId,
                    actorId, reason, ticketId, now);
            return changed;
        });
    }

    @Override
    public MerchantControlPlane.ProjectQuota putProjectQuota(
            MerchantControlPlane.ProjectQuota quota, long expectedVersion, String actorId,
            String reason, String ticketId) {
        return transaction(quota.tenantId(), "cannot update project quota", connection -> {
            MerchantControlPlane.ProjectQuota changed;
            String statementText = expectedVersion == -1 ? """
                    INSERT INTO project_quota
                      (tenant_id, project_id, quota_kind, environment, limit_value, version,
                       updated_at)
                    VALUES (?::uuid, ?::uuid, ?, ?, ?, 0, ?::timestamptz)
                    RETURNING tenant_id, project_id, quota_kind, environment, limit_value,
                              version, updated_at
                    """ : """
                    UPDATE project_quota
                       SET limit_value = ?, version = version + 1, updated_at = ?::timestamptz
                     WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND quota_kind = ?
                       AND environment = ? AND version = ?
                    RETURNING tenant_id, project_id, quota_kind, environment, limit_value,
                              version, updated_at
                    """;
            try (PreparedStatement statement = connection.prepareStatement(statementText)) {
                if (expectedVersion == -1) {
                    statement.setString(1, quota.tenantId().toString());
                    statement.setString(2, quota.projectId().toString());
                    statement.setString(3, quota.kind().name());
                    statement.setString(4, quota.environment() == null ? "all" : quota.environment());
                    statement.setLong(5, quota.limitValue());
                    statement.setString(6, quota.updatedAt().toString());
                } else {
                    statement.setLong(1, quota.limitValue());
                    statement.setString(2, quota.updatedAt().toString());
                    statement.setString(3, quota.tenantId().toString());
                    statement.setString(4, quota.projectId().toString());
                    statement.setString(5, quota.kind().name());
                    statement.setString(6, quota.environment() == null ? "all" : quota.environment());
                    statement.setLong(7, expectedVersion);
                }
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new OptimisticConflictException("project quota version was superseded");
                    }
                    changed = quota(result);
                }
            }
            insertControlAudit(connection, quota.tenantId(), "PROJECT_QUOTA_CHANGED", "project",
                    quota.projectId(), actorId, reason, ticketId, quota.updatedAt());
            return changed;
        });
    }

    @Override
    public MerchantControlPlane.MerchantProfile createProfile(
            MerchantControlPlane.MerchantProfile profile) {
        return transaction(profile.tenantId(), "cannot create merchant profile", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO merchant_profile
                      (id, tenant_id, project_id, merchant_id, legal_name,
                       entity_kind, registration_country, operating_region,
                       settlement_currency, business_category, risk_level,
                       document_references, profile_digest, verification_status, version,
                       created_at, updated_at)
                    VALUES (?::uuid, ?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            'PENDING', 0, ?::timestamptz, ?::timestamptz)
                    RETURNING id, tenant_id, project_id, merchant_id, legal_name,
                              entity_kind, registration_country, operating_region,
                              settlement_currency, business_category, risk_level,
                              document_references, profile_digest, verification_status, version,
                              created_at, updated_at
                    """)) {
                bindProfile(statement, profile);
                try (ResultSet result = statement.executeQuery()) {
                    return requiredProfile(result);
                }
            }
        });
    }

    @Override
    public MerchantControlPlane.MerchantProfile replaceProfile(
            MerchantControlPlane.MerchantProfile profile, long expectedVersion) {
        return transaction(profile.tenantId(), "cannot replace merchant profile", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE merchant_profile
                       SET legal_name = ?, entity_kind = ?, registration_country = ?,
                           operating_region = ?, settlement_currency = ?,
                           business_category = ?, risk_level = ?, document_references = ?,
                           profile_digest = ?,
                           verification_status = 'PENDING', version = version + 1,
                           updated_at = ?::timestamptz
                     WHERE tenant_id = ?::uuid AND id = ?::uuid AND version = ?
                    RETURNING id, tenant_id, project_id, merchant_id, legal_name,
                              entity_kind, registration_country, operating_region,
                              settlement_currency, business_category, risk_level,
                              document_references, profile_digest, verification_status, version,
                              created_at, updated_at
                    """)) {
                statement.setString(1, profile.legalName());
                statement.setString(2, profile.entityKind());
                statement.setString(3, profile.registrationCountry());
                statement.setString(4, profile.operatingRegion());
                statement.setString(5, profile.settlementCurrency());
                statement.setString(6, profile.businessCategory());
                statement.setString(7, profile.riskLevel().name());
                statement.setArray(8, stringArray(connection, profile.documentReferences()));
                statement.setString(9, profile.profileDigest());
                statement.setString(10, profile.updatedAt().toString());
                statement.setString(11, profile.tenantId().toString());
                statement.setString(12, profile.id().toString());
                statement.setLong(13, expectedVersion);
                try (ResultSet result = statement.executeQuery()) {
                    return requiredProfile(result);
                }
            }
        });
    }

    @Override
    public MerchantControlPlane.MerchantProfile recordVerification(
            MerchantControlPlane.VerificationDecision decision, Instant now) {
        return transaction(decision.tenantId(), "cannot record merchant verification",
                connection -> {
                    String currentDigest;
                    try (PreparedStatement statement = connection.prepareStatement("""
                            SELECT profile_digest FROM merchant_profile
                             WHERE tenant_id = ?::uuid AND id = ?::uuid
                             FOR UPDATE
                            """)) {
                        statement.setString(1, decision.tenantId().toString());
                        statement.setString(2, decision.profileId().toString());
                        try (ResultSet result = statement.executeQuery()) {
                            if (!result.next()) {
                                throw new OptimisticConflictException("merchant profile is missing");
                            }
                            currentDigest = result.getString(1);
                        }
                    }
                    if (!currentDigest.equals(decision.profileDigest())) {
                        throw new OptimisticConflictException(
                                "verification is bound to a stale profile digest");
                    }
                    try (PreparedStatement statement = connection.prepareStatement("""
                            INSERT INTO merchant_verification_decision
                              (id, tenant_id, profile_id, profile_digest, authority,
                               decision_reference, outcome, approver_ids, decided_at,
                               valid_until, recorded_at)
                            VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?::timestamptz,
                                    ?::timestamptz, ?::timestamptz)
                            """)) {
                        statement.setString(1, decision.id().toString());
                        statement.setString(2, decision.tenantId().toString());
                        statement.setString(3, decision.profileId().toString());
                        statement.setString(4, decision.profileDigest());
                        statement.setString(5, decision.authority());
                        statement.setString(6, decision.decisionReference());
                        statement.setString(7, decision.outcome().name());
                        statement.setArray(8, stringArray(connection, decision.approverIds()));
                        statement.setString(9, decision.decidedAt().toString());
                        statement.setString(10, decision.validUntil().toString());
                        statement.setString(11, now.toString());
                        statement.executeUpdate();
                    }
                    try (PreparedStatement statement = connection.prepareStatement("""
                            UPDATE merchant_profile
                               SET verification_status = ?, version = version + 1,
                                   updated_at = ?::timestamptz
                             WHERE tenant_id = ?::uuid AND id = ?::uuid
                               AND profile_digest = ?
                            RETURNING id, tenant_id, project_id, merchant_id, legal_name,
                                      entity_kind, registration_country, operating_region,
                                      settlement_currency, business_category, risk_level,
                                      document_references, profile_digest,
                                      verification_status, version, created_at, updated_at
                            """)) {
                        statement.setString(1, decision.outcome().name());
                        statement.setString(2, now.toString());
                        statement.setString(3, decision.tenantId().toString());
                        statement.setString(4, decision.profileId().toString());
                        statement.setString(5, decision.profileDigest());
                        try (ResultSet result = statement.executeQuery()) {
                            return requiredProfile(result);
                        }
                    }
                });
    }

    @Override
    public MerchantControlPlane.MerchantProfile expireVerification(UUID tenantId,
            UUID profileId, long expectedVersion, Instant now) {
        return transaction(tenantId, "cannot expire merchant verification", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE merchant_profile profile
                       SET verification_status = 'EXPIRED', version = version + 1,
                           updated_at = ?::timestamptz
                     WHERE profile.tenant_id = ?::uuid AND profile.id = ?::uuid
                       AND profile.version = ? AND profile.verification_status = 'VERIFIED'
                       AND NOT EXISTS (
                           SELECT 1 FROM merchant_verification_decision decision
                            WHERE decision.tenant_id = profile.tenant_id
                              AND decision.profile_id = profile.id
                              AND decision.profile_digest = profile.profile_digest
                              AND decision.outcome = 'VERIFIED'
                              AND decision.valid_until > ?::timestamptz)
                    RETURNING id, tenant_id, project_id, merchant_id, legal_name,
                              entity_kind, registration_country, operating_region,
                              settlement_currency, business_category, risk_level,
                              document_references, profile_digest, verification_status,
                              version, created_at, updated_at
                    """)) {
                statement.setString(1, now.toString());
                statement.setString(2, tenantId.toString());
                statement.setString(3, profileId.toString());
                statement.setLong(4, expectedVersion);
                statement.setString(5, now.toString());
                try (ResultSet result = statement.executeQuery()) {
                    return requiredProfile(result);
                }
            }
        });
    }

    @Override
    public MerchantControlPlane.Onboarding createOnboarding(
            MerchantControlPlane.Onboarding onboarding,
            List<MerchantControlPlane.StepDefinition> steps) {
        return transaction(onboarding.tenantId(), "cannot create merchant onboarding",
                connection -> {
                    MerchantControlPlane.Onboarding created;
                    boolean inserted;
                    try (PreparedStatement statement = connection.prepareStatement(
                            CREATE_ONBOARDING_SQL)) {
                        statement.setString(1, onboarding.id().toString());
                        statement.setString(2, onboarding.tenantId().toString());
                        statement.setString(3, onboarding.projectId().toString());
                        statement.setString(4, onboarding.merchantId().toString());
                        statement.setString(5, onboarding.providerAccountId().toString());
                        statement.setString(6, onboarding.requestDigest());
                        statement.setString(7, onboarding.idempotencyKey());
                        statement.setString(8, onboarding.requesterId());
                        statement.setString(9, onboarding.approvalExpiresAt().toString());
                        statement.setString(10, onboarding.createdAt().toString());
                        statement.setString(11, onboarding.updatedAt().toString());
                        try (ResultSet result = statement.executeQuery()) {
                            inserted = result.next();
                            created = inserted ? onboarding(result) : null;
                        }
                    }
                    if (!inserted) {
                        try (PreparedStatement statement = connection.prepareStatement("""
                                SELECT id, tenant_id, project_id, merchant_id,
                                       provider_account_id, request_digest, idempotency_key,
                                       requester_id, approver_id, state, version,
                                       approval_expires_at, created_at, updated_at
                                  FROM merchant_onboarding
                                 WHERE tenant_id = ?::uuid AND idempotency_key = ?
                                 FOR UPDATE
                                """)) {
                            statement.setString(1, onboarding.tenantId().toString());
                            statement.setString(2, onboarding.idempotencyKey());
                            try (ResultSet result = statement.executeQuery()) {
                                created = requiredOnboarding(result);
                            }
                        }
                        if (!sameOnboardingRequest(created, onboarding)) {
                            throw new OptimisticConflictException(
                                    "idempotency key is bound to another onboarding request");
                        }
                        return created;
                    }
                    try (PreparedStatement statement = connection.prepareStatement("""
                            INSERT INTO merchant_onboarding_step
                              (tenant_id, onboarding_id, step_name, step_order, has_side_effect,
                               idempotent, resumable, requires_approval, evidence_required,
                               state, fencing_token, attempt_count, next_attempt_at, created_at,
                               updated_at)
                            VALUES (?::uuid, ?::uuid, ?, ?, ?, true, true, ?, ?, 'PENDING', 0, 0,
                                    ?::timestamptz, ?::timestamptz, ?::timestamptz)
                            """)) {
                        for (MerchantControlPlane.StepDefinition step : steps) {
                            statement.setString(1, onboarding.tenantId().toString());
                            statement.setString(2, onboarding.id().toString());
                            statement.setString(3, step.name());
                            statement.setInt(4, step.order());
                            statement.setBoolean(5, step.hasSideEffect());
                            statement.setBoolean(6, step.requiresApproval());
                            statement.setString(7, step.evidenceRequired());
                            statement.setString(8, onboarding.createdAt().toString());
                            statement.setString(9, onboarding.createdAt().toString());
                            statement.setString(10, onboarding.createdAt().toString());
                            statement.addBatch();
                        }
                        int[] batchCounts = statement.executeBatch();
                        if (batchCounts.length != steps.size()
                                || Arrays.stream(batchCounts).anyMatch(count -> count == 0)) {
                            throw new SQLException("onboarding step initialization was incomplete");
                        }
                    }
                    return created;
                });
    }

    @Override
    public MerchantControlPlane.Onboarding approveOnboarding(UUID tenantId, UUID onboardingId,
            long expectedVersion, String requestDigest, String approverId, String reason,
            String ticketId, Instant now) {
        return transaction(tenantId, "cannot approve merchant onboarding", connection -> {
            MerchantControlPlane.Onboarding approved;
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE merchant_onboarding
                       SET state = 'RUNNING', approver_id = ?, approval_reason = ?,
                           approval_ticket_id = ?, approved_at = ?::timestamptz,
                           version = version + 1, updated_at = ?::timestamptz
                     WHERE tenant_id = ?::uuid AND id = ?::uuid
                       AND state = 'AWAITING_APPROVAL' AND version = ?
                       AND request_digest = ? AND requester_id <> ?
                       AND approval_expires_at > ?::timestamptz
                    RETURNING id, tenant_id, project_id, merchant_id, provider_account_id,
                              request_digest, idempotency_key, requester_id, approver_id,
                              state, version, approval_expires_at, created_at, updated_at
                    """)) {
                statement.setString(1, approverId);
                statement.setString(2, reason);
                statement.setString(3, ticketId);
                statement.setString(4, now.toString());
                statement.setString(5, now.toString());
                statement.setString(6, tenantId.toString());
                statement.setString(7, onboardingId.toString());
                statement.setLong(8, expectedVersion);
                statement.setString(9, requestDigest);
                statement.setString(10, approverId);
                statement.setString(11, now.toString());
                try (ResultSet result = statement.executeQuery()) {
                    approved = requiredOnboarding(result);
                }
            }
            insertControlAudit(connection, tenantId, "ONBOARDING_APPROVED", "onboarding",
                    onboardingId, approverId, reason, ticketId, now);
            return approved;
        });
    }

    @Override
    public Optional<MerchantControlPlane.StepLease> claimNextStep(UUID tenantId,
            UUID onboardingId, String workerId, Instant now, Duration leaseTtl) {
        return transaction(tenantId, "cannot claim merchant onboarding step", connection -> {
            String stepName;
            long previousFence;
            try (PreparedStatement statement = connection.prepareStatement(CLAIM_STEP_SQL)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, onboardingId.toString());
                statement.setString(3, now.toString());
                statement.setString(4, now.toString());
                statement.setString(5, now.toString());
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }
                    stepName = result.getString("step_name");
                    previousFence = result.getLong("fencing_token");
                }
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    CLAIM_STEP_UPDATE_SQL)) {
                statement.setString(1, workerId);
                statement.setString(2, now.plus(leaseTtl).toString());
                statement.setString(3, now.toString());
                statement.setString(4, tenantId.toString());
                statement.setString(5, onboardingId.toString());
                statement.setString(6, stepName);
                statement.setLong(7, previousFence);
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) {
                        throw new OptimisticConflictException(
                                "onboarding step fencing compare-and-set failed");
                    }
                    return Optional.of(new MerchantControlPlane.StepLease(tenantId,
                            onboardingId, stepName, workerId,
                            result.getLong("fencing_token"), result.getInt("attempt_count"),
                            now.plus(leaseTtl), onboardingId + ":" + stepName));
                }
            }
        });
    }

    @Override
    public void completeStep(MerchantControlPlane.StepLease lease, String evidenceDigest,
            Instant now) {
        transaction(lease.tenantId(), "cannot complete merchant onboarding step", connection -> {
            try (PreparedStatement statement = connection.prepareStatement(COMPLETE_STEP_SQL)) {
                statement.setString(1, evidenceDigest);
                statement.setString(2, now.toString());
                statement.setString(3, now.toString());
                statement.setString(4, lease.tenantId().toString());
                statement.setString(5, lease.onboardingId().toString());
                statement.setString(6, lease.stepName());
                statement.setString(7, lease.workerId());
                statement.setLong(8, lease.fencingToken());
                statement.setString(9, now.toString());
                requireOne(statement.executeUpdate(),
                        "stale worker cannot complete onboarding step");
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE merchant_onboarding workflow
                       SET state = 'COMPLETED', version = version + 1,
                           completed_at = ?::timestamptz, updated_at = ?::timestamptz
                     WHERE workflow.tenant_id = ?::uuid AND workflow.id = ?::uuid
                       AND workflow.state = 'RUNNING'
                       AND NOT EXISTS (
                           SELECT 1 FROM merchant_onboarding_step step
                            WHERE step.tenant_id = workflow.tenant_id
                              AND step.onboarding_id = workflow.id
                              AND step.state <> 'COMPLETED')
                    """)) {
                statement.setString(1, now.toString());
                statement.setString(2, now.toString());
                statement.setString(3, lease.tenantId().toString());
                statement.setString(4, lease.onboardingId().toString());
                statement.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public void retryStep(MerchantControlPlane.StepLease lease, String safeErrorCode,
            Instant now, Duration retryDelay) {
        transaction(lease.tenantId(), "cannot retry merchant onboarding step", connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE merchant_onboarding_step
                       SET state = 'RETRY', lease_owner = NULL, lease_until = NULL,
                           next_attempt_at = ?::timestamptz, last_error_code = ?,
                           updated_at = ?::timestamptz
                     WHERE tenant_id = ?::uuid AND onboarding_id = ?::uuid AND step_name = ?
                       AND state = 'RUNNING' AND lease_owner = ? AND fencing_token = ?
                       AND lease_until > ?::timestamptz
                    """)) {
                statement.setString(1, now.plus(retryDelay).toString());
                statement.setString(2, safeErrorCode);
                statement.setString(3, now.toString());
                statement.setString(4, lease.tenantId().toString());
                statement.setString(5, lease.onboardingId().toString());
                statement.setString(6, lease.stepName());
                statement.setString(7, lease.workerId());
                statement.setLong(8, lease.fencingToken());
                statement.setString(9, now.toString());
                requireOne(statement.executeUpdate(),
                        "stale worker cannot retry onboarding step");
            }
            return null;
        });
    }

    private static void bindProfile(PreparedStatement statement,
            MerchantControlPlane.MerchantProfile profile) throws SQLException {
        statement.setString(1, profile.id().toString());
        statement.setString(2, profile.tenantId().toString());
        statement.setString(3, profile.projectId().toString());
        statement.setString(4, profile.merchantId().toString());
        statement.setString(5, profile.legalName());
        statement.setString(6, profile.entityKind());
        statement.setString(7, profile.registrationCountry());
        statement.setString(8, profile.operatingRegion());
        statement.setString(9, profile.settlementCurrency());
        statement.setString(10, profile.businessCategory());
        statement.setString(11, profile.riskLevel().name());
        statement.setArray(12, stringArray(statement.getConnection(),
                profile.documentReferences()));
        statement.setString(13, profile.profileDigest());
        statement.setString(14, profile.createdAt().toString());
        statement.setString(15, profile.updatedAt().toString());
    }

    private static Array stringArray(Connection connection, List<String> values)
            throws SQLException {
        return connection.createArrayOf("text", values.toArray(String[]::new));
    }

    private static MerchantControlPlane.Tenant requiredTenant(ResultSet result)
            throws SQLException {
        if (!result.next()) {
            throw new OptimisticConflictException("tenant version or state was superseded");
        }
        return new MerchantControlPlane.Tenant(result.getObject("id", UUID.class),
                result.getString("external_reference"), result.getString("code"),
                MerchantControlPlane.TenantState.valueOf(result.getString("state")),
                result.getLong("version"), result.getTimestamp("created_at").toInstant(),
                result.getTimestamp("updated_at").toInstant());
    }

    private static MerchantControlPlane.Project project(ResultSet result) throws SQLException {
        return new MerchantControlPlane.Project(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class), result.getString("code"),
                result.getString("environment"), result.getBoolean("enabled"),
                result.getLong("version"), result.getTimestamp("created_at").toInstant(),
                result.getTimestamp("updated_at").toInstant());
    }

    private static MerchantControlPlane.ProjectQuota quota(ResultSet result) throws SQLException {
        return new MerchantControlPlane.ProjectQuota(result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                MerchantControlPlane.QuotaKind.valueOf(result.getString("quota_kind")),
                "all".equals(result.getString("environment"))
                        ? null : result.getString("environment"), result.getLong("limit_value"),
                result.getLong("version"), result.getTimestamp("updated_at").toInstant());
    }

    private static MerchantControlPlane.MerchantProfile requiredProfile(ResultSet result)
            throws SQLException {
        if (!result.next()) {
            throw new OptimisticConflictException("merchant profile version was superseded");
        }
        String[] references = (String[]) result.getArray("document_references").getArray();
        return new MerchantControlPlane.MerchantProfile(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("merchant_id", UUID.class), result.getString("legal_name"),
                result.getString("entity_kind"), result.getString("registration_country"),
                result.getString("operating_region"), result.getString("settlement_currency"),
                result.getString("business_category"),
                MerchantControlPlane.RiskLevel.valueOf(result.getString("risk_level")),
                List.of(references),
                result.getString("profile_digest"),
                MerchantControlPlane.VerificationStatus.valueOf(
                        result.getString("verification_status")), result.getLong("version"),
                result.getTimestamp("created_at").toInstant(),
                result.getTimestamp("updated_at").toInstant());
    }

    private static MerchantControlPlane.Onboarding requiredOnboarding(ResultSet result)
            throws SQLException {
        if (!result.next()) {
            throw new OptimisticConflictException("onboarding state or version was superseded");
        }
        return onboarding(result);
    }

    private static MerchantControlPlane.Onboarding onboarding(ResultSet result)
            throws SQLException {
        return new MerchantControlPlane.Onboarding(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("merchant_id", UUID.class),
                result.getObject("provider_account_id", UUID.class),
                result.getString("request_digest"), result.getString("idempotency_key"),
                result.getString("requester_id"), result.getString("approver_id"),
                MerchantControlPlane.OnboardingState.valueOf(result.getString("state")),
                result.getLong("version"),
                result.getTimestamp("approval_expires_at").toInstant(),
                result.getTimestamp("created_at").toInstant(),
                result.getTimestamp("updated_at").toInstant());
    }

    private static boolean sameOnboardingRequest(MerchantControlPlane.Onboarding existing,
            MerchantControlPlane.Onboarding requested) {
        return existing.id().equals(requested.id())
                && existing.tenantId().equals(requested.tenantId())
                && existing.projectId().equals(requested.projectId())
                && existing.merchantId().equals(requested.merchantId())
                && existing.providerAccountId().equals(requested.providerAccountId())
                && existing.requestDigest().equals(requested.requestDigest())
                && existing.requesterId().equals(requested.requesterId());
    }

    private static void insertControlAudit(Connection connection, UUID tenantId, String action,
            String targetType, UUID targetId, String actorId, String reason, String ticketId,
            Instant now)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO merchant_control_audit
                  (id, tenant_id, action, target_type, target_id, actor_id, reason,
                   ticket_id, occurred_at)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?::timestamptz)
                """)) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, tenantId.toString());
            statement.setString(3, action);
            statement.setString(4, targetType);
            statement.setString(5, targetId.toString());
            statement.setString(6, actorId);
            statement.setString(7, reason);
            statement.setString(8, ticketId);
            statement.setString(9, now.toString());
            statement.executeUpdate();
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private <T> T transaction(UUID tenantId, String message, SqlWork<T> work) {
        Objects.requireNonNull(tenantId, "tenantId");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                T result = work.execute(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                if (failure instanceof RuntimeException runtime) {
                    throw runtime;
                }
                throw new ControlPlaneStoreException(message, failure);
            }
        } catch (SQLException failure) {
            throw new ControlPlaneStoreException(message, failure);
        }
    }

    static void requireOne(int changed, String message) {
        if (changed != 1) {
            throw new OptimisticConflictException(message);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T execute(Connection connection) throws SQLException;
    }

    public static final class ControlPlaneStoreException extends IllegalStateException {
        @java.io.Serial
        private static final long serialVersionUID = 1L;

        public ControlPlaneStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static final class OptimisticConflictException extends IllegalStateException {
        @java.io.Serial
        private static final long serialVersionUID = 1L;

        public OptimisticConflictException(String message) {
            super(message);
        }
    }
}
