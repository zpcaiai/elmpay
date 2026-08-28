-- B30 durable, resumable onboarding with digest-bound four-eyes approval and fenced steps.
CREATE TABLE IF NOT EXISTS merchant_onboarding (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenant_registry(id),
    project_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key text NOT NULL,
    requester_id text NOT NULL,
    approver_id text,
    approval_reason text,
    approval_ticket_id text,
    approved_at timestamptz,
    approval_expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN
        ('AWAITING_APPROVAL', 'RUNNING', 'COMPLETED', 'SUSPENDED')),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, project_id) REFERENCES project_registry(tenant_id, id),
    CHECK (approval_expires_at <= created_at + interval '72 hours'),
    CHECK ((state = 'AWAITING_APPROVAL' AND approver_id IS NULL AND approved_at IS NULL)
        OR (state <> 'AWAITING_APPROVAL' AND approver_id IS NOT NULL
            AND approver_id <> requester_id AND approved_at IS NOT NULL)),
    CHECK ((state = 'COMPLETED' AND completed_at IS NOT NULL)
        OR (state <> 'COMPLETED' AND completed_at IS NULL))
);

CREATE TABLE IF NOT EXISTS merchant_onboarding_step (
    tenant_id uuid NOT NULL,
    onboarding_id uuid NOT NULL,
    step_name text NOT NULL,
    step_order integer NOT NULL CHECK (step_order > 0),
    has_side_effect boolean NOT NULL,
    idempotent boolean NOT NULL CHECK (idempotent),
    resumable boolean NOT NULL CHECK (resumable),
    requires_approval boolean NOT NULL,
    evidence_required text NOT NULL,
    state text NOT NULL CHECK (state IN ('PENDING', 'RUNNING', 'RETRY', 'COMPLETED')),
    lease_owner text,
    lease_until timestamptz,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL,
    last_error_code text,
    evidence_digest char(64) CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, onboarding_id, step_name),
    UNIQUE (tenant_id, onboarding_id, step_order),
    FOREIGN KEY (tenant_id, onboarding_id) REFERENCES merchant_onboarding(tenant_id, id),
    CHECK ((step_name = 'import_credentials' AND step_order = 10
             AND has_side_effect AND NOT requires_approval
             AND evidence_required = 'credential_reference')
        OR (step_name = 'verify_domain' AND step_order = 20
             AND NOT has_side_effect AND NOT requires_approval
             AND evidence_required = 'dns_txt_record')
        OR (step_name = 'verify_callback' AND step_order = 30
             AND has_side_effect AND NOT requires_approval
             AND evidence_required = 'callback_roundtrip_id')
        OR (step_name = 'set_limits' AND step_order = 40
             AND NOT has_side_effect AND NOT requires_approval
             AND evidence_required = 'limit_snapshot')
        OR (step_name = 'approve' AND step_order = 50
             AND NOT has_side_effect AND requires_approval
             AND evidence_required = 'approval_record')
        OR (step_name = 'go_live' AND step_order = 60
             AND has_side_effect AND NOT requires_approval
             AND evidence_required = 'binding_state')),
    CHECK ((state = 'RUNNING' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR (state <> 'RUNNING' AND lease_owner IS NULL AND lease_until IS NULL)),
    CHECK ((state = 'COMPLETED' AND completed_at IS NOT NULL
            AND evidence_digest IS NOT NULL)
        OR (state <> 'COMPLETED' AND completed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS merchant_onboarding_step_due_idx
    ON merchant_onboarding_step (tenant_id, onboarding_id, next_attempt_at, step_order)
    WHERE state IN ('PENDING', 'RETRY', 'RUNNING');

ALTER TABLE merchant_onboarding ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_onboarding FORCE ROW LEVEL SECURITY;
ALTER TABLE merchant_onboarding_step ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_onboarding_step FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS merchant_onboarding_tenant_policy ON merchant_onboarding;
CREATE POLICY merchant_onboarding_tenant_policy ON merchant_onboarding
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS merchant_onboarding_step_tenant_policy ON merchant_onboarding_step;
CREATE POLICY merchant_onboarding_step_tenant_policy ON merchant_onboarding_step
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Rollback: drop merchant_onboarding_step then merchant_onboarding.
