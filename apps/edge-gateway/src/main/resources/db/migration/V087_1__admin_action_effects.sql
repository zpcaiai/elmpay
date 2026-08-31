-- Cross-service Admin Action command queue and committed-effect receipts.
-- Queue presence is not a successful effect and is never certification evidence.

-- Existing pre-typed approvals/dispatches cannot safely infer LIST_ADD versus LIST_REMOVE.
-- They stay explicitly untyped and the enqueue service rejects them; operators must re-propose.
ALTER TABLE admin_approval
    ADD COLUMN IF NOT EXISTS operation_code text NOT NULL DEFAULT 'LEGACY_UNTYPED';
ALTER TABLE admin_approval ADD COLUMN IF NOT EXISTS project_id uuid;
ALTER TABLE admin_approval ALTER COLUMN operation_code DROP DEFAULT;
ALTER TABLE admin_approval DROP CONSTRAINT IF EXISTS admin_approval_operation_code_check;
ALTER TABLE admin_approval ADD CONSTRAINT admin_approval_operation_code_check CHECK
    (operation_code IN ('CASE_CLOSE','LIST_ADD','LIST_REMOVE','REFUND_OVERRIDE',
                        'ROLLOUT_APPROVAL','LEGACY_UNTYPED'));
ALTER TABLE admin_action_dispatch
    ADD COLUMN IF NOT EXISTS operation_code text NOT NULL DEFAULT 'LEGACY_UNTYPED';
ALTER TABLE admin_action_dispatch ADD COLUMN IF NOT EXISTS project_id uuid;
ALTER TABLE admin_action_dispatch ALTER COLUMN operation_code DROP DEFAULT;
ALTER TABLE admin_action_dispatch DROP CONSTRAINT IF EXISTS admin_dispatch_operation_code_check;
ALTER TABLE admin_action_dispatch ADD CONSTRAINT admin_dispatch_operation_code_check CHECK
    (operation_code IN ('CASE_CLOSE','LIST_ADD','LIST_REMOVE','REFUND_OVERRIDE',
                        'ROLLOUT_APPROVAL','LEGACY_UNTYPED'));

CREATE TABLE IF NOT EXISTS admin_domain_command (
    command_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    idempotency_key char(64) NOT NULL
        CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    command_digest char(64) NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    kind text NOT NULL
        CHECK (kind IN ('CASE_CLOSE','LIST_CHANGE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
    operation_code text NOT NULL CHECK (operation_code IN
        ('CASE_CLOSE','LIST_ADD','LIST_REMOVE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
    consumer_group text NOT NULL CHECK (consumer_group IN ('RISK','PAYMENT','ROLLOUT')),
    target_id text NOT NULL CHECK (target_id ~ '^[A-Za-z0-9._:@/-]{1,160}$'),
    proposal_digest char(64) NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    approval_version bigint NOT NULL CHECK (approval_version = 2),
    proposer_digest char(64) NOT NULL CHECK (proposer_digest ~ '^[0-9a-f]{64}$'),
    approver_digest char(64) NOT NULL CHECK (approver_digest ~ '^[0-9a-f]{64}$'),
    approval_expires_at timestamptz NOT NULL,
    source_dispatch_fencing_token bigint NOT NULL CHECK (source_dispatch_fencing_token > 0),
    state text NOT NULL
        CHECK (state IN ('PENDING','CLAIMED','RETRY','UNKNOWN','APPLIED','BLOCKED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    next_attempt_at timestamptz,
    lease_owner text,
    lease_until timestamptz,
    consumer_fencing_token bigint NOT NULL DEFAULT 0 CHECK (consumer_fencing_token >= 0),
    failure_code text CHECK (failure_code IS NULL
        OR failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    diagnostic_digest char(64)
        CHECK (diagnostic_digest IS NULL OR diagnostic_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, command_id),
    UNIQUE (tenant_id, idempotency_key),
    UNIQUE (tenant_id, command_id, project_id, idempotency_key, command_digest, kind,
            operation_code, consumer_group, target_id, proposal_digest, policy_digest),
    CHECK (proposer_digest <> approver_digest),
    CHECK ((kind = 'CASE_CLOSE' AND operation_code = 'CASE_CLOSE'
             AND consumer_group = 'RISK')
        OR (kind = 'LIST_CHANGE' AND operation_code IN ('LIST_ADD','LIST_REMOVE')
             AND consumer_group = 'RISK')
        OR (kind = 'REFUND_OVERRIDE' AND operation_code = 'REFUND_OVERRIDE'
             AND consumer_group = 'PAYMENT')
        OR (kind = 'ROLLOUT_APPROVAL' AND operation_code = 'ROLLOUT_APPROVAL'
             AND consumer_group = 'ROLLOUT')),
    CHECK (created_at < approval_expires_at AND updated_at >= created_at),
    CHECK ((state = 'CLAIMED' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL
            AND next_attempt_at IS NULL)
        OR (state IN ('PENDING','RETRY','UNKNOWN') AND lease_owner IS NULL
            AND lease_until IS NULL AND next_attempt_at IS NOT NULL)
        OR (state IN ('APPLIED','BLOCKED') AND lease_owner IS NULL
            AND lease_until IS NULL AND next_attempt_at IS NULL)),
    CHECK ((state IN ('PENDING','CLAIMED','APPLIED') AND failure_code IS NULL
            AND diagnostic_digest IS NULL)
        OR (state IN ('RETRY','UNKNOWN','BLOCKED') AND failure_code IS NOT NULL
            AND diagnostic_digest IS NOT NULL))
);

-- This contains only a consumer group, tenant UUID, and scheduling metadata. Payload rows
-- remain FORCE-RLS and cannot be read until the selected tenant context is established.
CREATE TABLE IF NOT EXISTS admin_domain_command_signal (
    consumer_group text NOT NULL CHECK (consumer_group IN ('RISK','PAYMENT','ROLLOUT')),
    tenant_id uuid NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    lease_owner text,
    lease_until timestamptz,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    PRIMARY KEY (consumer_group, tenant_id),
    CHECK ((lease_owner IS NULL AND lease_until IS NULL)
        OR (lease_owner IS NOT NULL AND lease_until IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS admin_action_effect_receipt (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    receipt_id uuid NOT NULL UNIQUE,
    idempotency_key char(64) NOT NULL
        CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    approval_id uuid NOT NULL,
    command_digest char(64) NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    kind text NOT NULL
        CHECK (kind IN ('CASE_CLOSE','LIST_CHANGE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
    operation_code text NOT NULL CHECK (operation_code IN
        ('CASE_CLOSE','LIST_ADD','LIST_REMOVE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
    consumer_group text NOT NULL CHECK (consumer_group IN ('RISK','PAYMENT','ROLLOUT')),
    target_id text NOT NULL CHECK (target_id ~ '^[A-Za-z0-9._:@/-]{1,160}$'),
    proposal_digest char(64) NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    consumer_fencing_token bigint NOT NULL CHECK (consumer_fencing_token > 0),
    effect_digest char(64) NOT NULL CHECK (effect_digest ~ '^[0-9a-f]{64}$'),
    executed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key),
    UNIQUE (tenant_id, approval_id),
    FOREIGN KEY (tenant_id, approval_id, project_id, idempotency_key, command_digest,
                 kind, operation_code, consumer_group, target_id, proposal_digest,
                 policy_digest)
        REFERENCES admin_domain_command
          (tenant_id, command_id, project_id, idempotency_key, command_digest, kind,
           operation_code, consumer_group, target_id, proposal_digest, policy_digest)
);

CREATE TABLE IF NOT EXISTS admin_action_diagnostic_audit (
    sequence_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    operator_digest char(64) NOT NULL CHECK (operator_digest ~ '^[0-9a-f]{64}$'),
    service_name text NOT NULL CHECK (service_name ~ '^[a-z][a-z0-9-]{1,62}$'),
    projection_digest char(64) NOT NULL CHECK (projection_digest ~ '^[0-9a-f]{64}$'),
    event_digest char(64) NOT NULL UNIQUE CHECK (event_digest ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS admin_domain_command_due_idx
    ON admin_domain_command (tenant_id, consumer_group, next_attempt_at)
    WHERE state IN ('PENDING','RETRY','UNKNOWN','CLAIMED');
CREATE INDEX IF NOT EXISTS admin_domain_command_signal_due_idx
    ON admin_domain_command_signal (consumer_group, next_attempt_at);

CREATE OR REPLACE FUNCTION elmpay_admin_typed_binding_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.operation_code IS DISTINCT FROM OLD.operation_code THEN
        RAISE EXCEPTION 'admin project and operation binding is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_command_transition_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_expected_group text := CASE session_user
        WHEN 'elmpay_edge_gateway' THEN 'PAYMENT'
        WHEN 'elmpay_risk_engine' THEN 'RISK'
        WHEN 'elmpay_worker' THEN 'ROLLOUT'
        WHEN 'elmpay_migrator' THEN NULL
        ELSE '__DENIED__'
    END;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'admin domain commands cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF session_user NOT IN ('elmpay_edge_gateway', 'elmpay_migrator')
           OR NEW.state <> 'PENDING' OR NEW.attempts <> 0
           OR NEW.consumer_fencing_token <> 0 OR NEW.lease_owner IS NOT NULL
           OR NEW.lease_until IS NOT NULL OR NEW.failure_code IS NOT NULL
           OR NEW.diagnostic_digest IS NOT NULL
           OR NEW.approval_expires_at <= v_now THEN
            RAISE EXCEPTION 'admin domain command insert is not canonical'
                USING ERRCODE = '55000';
        END IF;
        -- Application clocks are never authoritative for queue ordering or TTL checks.
        NEW.created_at := v_now;
        NEW.updated_at := v_now;
        NEW.next_attempt_at := v_now;
        RETURN NEW;
    END IF;
    IF v_expected_group = '__DENIED__'
       OR (v_expected_group IS NOT NULL AND OLD.consumer_group <> v_expected_group) THEN
        RAISE EXCEPTION 'admin command caller cannot mutate this consumer group'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.command_id <> OLD.command_id OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.project_id <> OLD.project_id
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.command_digest <> OLD.command_digest OR NEW.kind <> OLD.kind
       OR NEW.operation_code <> OLD.operation_code
       OR NEW.consumer_group <> OLD.consumer_group OR NEW.target_id <> OLD.target_id
       OR NEW.proposal_digest <> OLD.proposal_digest
       OR NEW.policy_digest <> OLD.policy_digest
       OR NEW.approval_version <> OLD.approval_version
       OR NEW.proposer_digest <> OLD.proposer_digest
       OR NEW.approver_digest <> OLD.approver_digest
           OR NEW.approval_expires_at <> OLD.approval_expires_at
           OR NEW.source_dispatch_fencing_token <> OLD.source_dispatch_fencing_token
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'invalid admin domain command transition' USING ERRCODE = '55000';
    END IF;
    IF OLD.state IN ('PENDING','RETRY','UNKNOWN') AND NEW.state = 'CLAIMED' THEN
        IF NEW.attempts <> OLD.attempts + 1
           OR NEW.consumer_fencing_token <> OLD.consumer_fencing_token + 1
           OR NEW.lease_owner IS NULL OR btrim(NEW.lease_owner) = ''
           OR NEW.lease_until <= v_now
           OR NEW.lease_until > v_now + interval '60 seconds'
           OR NEW.next_attempt_at IS NOT NULL OR NEW.failure_code IS NOT NULL
           OR NEW.diagnostic_digest IS NOT NULL THEN
            RAISE EXCEPTION 'invalid admin domain command claim' USING ERRCODE = '55000';
        END IF;
    ELSIF OLD.state IN ('PENDING','RETRY','UNKNOWN') AND NEW.state = 'BLOCKED' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.consumer_fencing_token <> OLD.consumer_fencing_token
           OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
           OR NEW.next_attempt_at IS NOT NULL OR NEW.failure_code IS NULL
           OR NEW.diagnostic_digest IS NULL THEN
            RAISE EXCEPTION 'invalid unclaimed admin command block'
                USING ERRCODE = '55000';
        END IF;
    ELSIF OLD.state = 'CLAIMED' AND NEW.state = 'UNKNOWN'
          AND OLD.lease_until <= v_now THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.consumer_fencing_token <> OLD.consumer_fencing_token
           OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
           OR NEW.next_attempt_at IS NULL OR NEW.failure_code <> 'STALE_LEASE'
           OR NEW.diagnostic_digest IS NULL OR NEW.approval_expires_at <= v_now
           OR NEW.next_attempt_at >= NEW.approval_expires_at THEN
            RAISE EXCEPTION 'invalid stale admin command recovery' USING ERRCODE = '55000';
        END IF;
    ELSIF OLD.state = 'CLAIMED' AND NEW.state IN ('RETRY','UNKNOWN') THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.consumer_fencing_token <> OLD.consumer_fencing_token
           OR OLD.lease_until <= v_now
           OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
           OR NEW.next_attempt_at IS NULL OR NEW.failure_code IS NULL
           OR NEW.diagnostic_digest IS NULL
           OR NEW.next_attempt_at >= NEW.approval_expires_at THEN
            RAISE EXCEPTION 'invalid admin command retry' USING ERRCODE = '55000';
        END IF;
    ELSIF OLD.state = 'CLAIMED' AND NEW.state = 'APPLIED' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.consumer_fencing_token <> OLD.consumer_fencing_token
           OR OLD.lease_until <= v_now
           OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
           OR NEW.next_attempt_at IS NOT NULL OR NEW.failure_code IS NOT NULL
           OR NEW.diagnostic_digest IS NOT NULL
           OR NEW.approval_expires_at <= v_now THEN
            RAISE EXCEPTION 'invalid admin command effect commit' USING ERRCODE = '55000';
        END IF;
    ELSIF OLD.state = 'CLAIMED' AND NEW.state = 'BLOCKED' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.consumer_fencing_token <> OLD.consumer_fencing_token
           OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
           OR NEW.next_attempt_at IS NOT NULL OR NEW.failure_code IS NULL
           OR NEW.diagnostic_digest IS NULL
           OR ((OLD.lease_until <= v_now OR NEW.approval_expires_at <= v_now)
               AND NEW.failure_code <> 'APPROVAL_EXPIRED') THEN
            RAISE EXCEPTION 'invalid claimed admin command block' USING ERRCODE = '55000';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid admin domain command transition' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at := v_now;
    RETURN NEW;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_effect_receipt_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
    IF NEW.executed_at > clock_timestamp() OR NOT EXISTS (
        SELECT 1
          FROM admin_domain_command command
         WHERE command.tenant_id = NEW.tenant_id
           AND command.command_id = NEW.approval_id
           AND command.project_id = NEW.project_id
           AND command.idempotency_key = NEW.idempotency_key
           AND command.command_digest = NEW.command_digest
           AND command.kind = NEW.kind
           AND command.operation_code = NEW.operation_code
           AND command.consumer_group = NEW.consumer_group
           AND command.target_id = NEW.target_id
           AND command.proposal_digest = NEW.proposal_digest
           AND command.policy_digest = NEW.policy_digest
           AND command.consumer_fencing_token = NEW.consumer_fencing_token
           AND command.state = 'APPLIED'
           AND command.updated_at = NEW.executed_at
           AND command.approval_expires_at > NEW.executed_at
    ) THEN
        RAISE EXCEPTION 'admin effect receipt has no exact committed command'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_action_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
    RAISE EXCEPTION 'admin action effects are append only' USING ERRCODE = '55000';
END;
$elmpay$;

DROP TRIGGER IF EXISTS admin_domain_command_transition_guard ON admin_domain_command;
CREATE TRIGGER admin_domain_command_transition_guard
BEFORE INSERT OR UPDATE OR DELETE ON admin_domain_command
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_command_transition_guard();
DROP TRIGGER IF EXISTS admin_approval_typed_binding_guard ON admin_approval;
CREATE TRIGGER admin_approval_typed_binding_guard
BEFORE UPDATE ON admin_approval
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_typed_binding_guard();
DROP TRIGGER IF EXISTS admin_dispatch_typed_binding_guard ON admin_action_dispatch;
CREATE TRIGGER admin_dispatch_typed_binding_guard
BEFORE UPDATE ON admin_action_dispatch
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_typed_binding_guard();
DROP TRIGGER IF EXISTS admin_action_effect_receipt_immutable
    ON admin_action_effect_receipt;
DROP TRIGGER IF EXISTS admin_action_effect_receipt_binding_guard
    ON admin_action_effect_receipt;
CREATE TRIGGER admin_action_effect_receipt_binding_guard
BEFORE INSERT ON admin_action_effect_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_effect_receipt_guard();
CREATE TRIGGER admin_action_effect_receipt_immutable
BEFORE UPDATE OR DELETE ON admin_action_effect_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_action_immutable();
DROP TRIGGER IF EXISTS admin_action_diagnostic_audit_immutable
    ON admin_action_diagnostic_audit;
CREATE TRIGGER admin_action_diagnostic_audit_immutable
BEFORE UPDATE OR DELETE ON admin_action_diagnostic_audit
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_action_immutable();

ALTER TABLE admin_domain_command ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_domain_command FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_domain_command_signal ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_domain_command_signal FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_action_effect_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_effect_receipt FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_action_diagnostic_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_diagnostic_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS admin_domain_command_tenant_policy ON admin_domain_command;
CREATE POLICY admin_domain_command_tenant_policy ON admin_domain_command
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
       AND (session_user = 'elmpay_edge_gateway'
         OR (session_user = 'elmpay_risk_engine' AND consumer_group = 'RISK')
         OR (session_user = 'elmpay_worker' AND consumer_group = 'ROLLOUT')
         OR session_user = 'elmpay_migrator'))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
       AND (session_user = 'elmpay_edge_gateway'
         OR (session_user = 'elmpay_risk_engine' AND consumer_group = 'RISK')
         OR (session_user = 'elmpay_worker' AND consumer_group = 'ROLLOUT')
         OR session_user = 'elmpay_migrator'));
DROP POLICY IF EXISTS admin_domain_command_signal_group_policy
    ON admin_domain_command_signal;
CREATE POLICY admin_domain_command_signal_group_policy ON admin_domain_command_signal
    USING ((session_user = 'elmpay_edge_gateway'
             AND consumer_group IN ('RISK','PAYMENT','ROLLOUT'))
        OR (session_user = 'elmpay_risk_engine' AND consumer_group = 'RISK')
        OR (session_user = 'elmpay_worker' AND consumer_group = 'ROLLOUT')
        OR session_user = 'elmpay_migrator')
    WITH CHECK ((session_user = 'elmpay_edge_gateway'
            AND consumer_group IN ('RISK','PAYMENT','ROLLOUT'))
        OR (session_user = 'elmpay_risk_engine' AND consumer_group = 'RISK')
        OR (session_user = 'elmpay_worker' AND consumer_group = 'ROLLOUT')
        OR session_user = 'elmpay_migrator');
DROP POLICY IF EXISTS admin_action_effect_receipt_tenant_policy
    ON admin_action_effect_receipt;
CREATE POLICY admin_action_effect_receipt_tenant_policy ON admin_action_effect_receipt
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
       AND (session_user = 'elmpay_edge_gateway'
         OR (session_user = 'elmpay_risk_engine' AND consumer_group = 'RISK')
         OR (session_user = 'elmpay_worker' AND consumer_group = 'ROLLOUT')
         OR session_user = 'elmpay_migrator'))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
       AND ((session_user = 'elmpay_edge_gateway' AND consumer_group = 'PAYMENT')
         OR (session_user = 'elmpay_risk_engine' AND consumer_group = 'RISK')
         OR (session_user = 'elmpay_worker' AND consumer_group = 'ROLLOUT')
         OR session_user = 'elmpay_migrator'));
DROP POLICY IF EXISTS admin_action_diagnostic_audit_tenant_policy
    ON admin_action_diagnostic_audit;
CREATE POLICY admin_action_diagnostic_audit_tenant_policy ON admin_action_diagnostic_audit
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- elmpay.admin-command-db-api.v1
-- Runtime identities have no base-table DML. These fixed-search-path routines are the only
-- cross-domain queue capability; they authorize the login identity via session_user because
-- current_user is the definer inside SECURITY DEFINER functions.
CREATE OR REPLACE FUNCTION elmpay_admin_enqueue_command(
    p_command_id uuid, p_tenant_id uuid, p_project_id uuid, p_idempotency_key text,
    p_command_digest text, p_kind text, p_operation_code text, p_consumer_group text,
    p_target_id text, p_proposal_digest text, p_policy_digest text,
    p_approval_version bigint, p_proposer_digest text, p_approver_digest text,
    p_approval_expires_at timestamptz, p_source_dispatch_fencing_token bigint)
RETURNS TABLE(outcome text, command_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_inserted integer;
    v_now timestamptz := clock_timestamp();
    v_command admin_domain_command%ROWTYPE;
BEGIN
    -- elmpay.admin-command-db-api.v1:edge-enqueue
    IF session_user <> 'elmpay_edge_gateway'
       OR NULLIF(current_setting('app.tenant_id', true), '')::uuid IS DISTINCT FROM p_tenant_id
       OR p_approval_expires_at <= v_now THEN
        RAISE EXCEPTION 'admin command enqueue is not authorized or has expired'
            USING ERRCODE = '42501';
    END IF;
    INSERT INTO admin_domain_command
      (command_id, tenant_id, project_id, idempotency_key, command_digest, kind,
       operation_code, consumer_group, target_id, proposal_digest, policy_digest,
       approval_version, proposer_digest, approver_digest, approval_expires_at,
       source_dispatch_fencing_token, state, attempts, next_attempt_at,
       consumer_fencing_token, created_at, updated_at)
    VALUES (p_command_id, p_tenant_id, p_project_id, p_idempotency_key,
            p_command_digest, p_kind, p_operation_code, p_consumer_group, p_target_id,
            p_proposal_digest, p_policy_digest, p_approval_version, p_proposer_digest,
            p_approver_digest, p_approval_expires_at, p_source_dispatch_fencing_token,
            'PENDING', 0, v_now, 0, v_now, v_now)
    ON CONFLICT (tenant_id, idempotency_key) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;

    SELECT * INTO STRICT v_command FROM admin_domain_command command
     WHERE command.tenant_id = p_tenant_id
       AND command.idempotency_key = p_idempotency_key FOR UPDATE;
    IF v_command.command_id <> p_command_id OR v_command.project_id <> p_project_id
       OR v_command.command_digest <> p_command_digest OR v_command.kind <> p_kind
       OR v_command.operation_code <> p_operation_code
       OR v_command.consumer_group <> p_consumer_group OR v_command.target_id <> p_target_id
       OR v_command.proposal_digest <> p_proposal_digest
       OR v_command.policy_digest <> p_policy_digest
       OR v_command.approval_version <> p_approval_version
       OR v_command.proposer_digest <> p_proposer_digest
       OR v_command.approver_digest <> p_approver_digest
       OR v_command.approval_expires_at <> p_approval_expires_at THEN
        RAISE EXCEPTION 'admin command idempotency binding conflict'
            USING ERRCODE = '23505';
    END IF;
    INSERT INTO admin_domain_command_signal
      (consumer_group, tenant_id, next_attempt_at)
    VALUES (v_command.consumer_group, v_command.tenant_id, v_command.created_at)
    ON CONFLICT (consumer_group, tenant_id) DO UPDATE
       SET next_attempt_at = LEAST(admin_domain_command_signal.next_attempt_at,
                                   EXCLUDED.next_attempt_at);
    outcome := CASE WHEN v_inserted = 1 THEN 'ENQUEUED' ELSE 'EXISTING' END;
    command_state := v_command.state;
    RETURN NEXT;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_observe_command(
    p_tenant_id uuid, p_idempotency_key text)
RETURNS TABLE(command_id uuid, project_id uuid, idempotency_key text,
    command_digest text, kind text, operation_code text, consumer_group text,
    target_id text, proposal_digest text, policy_digest text, approval_version bigint,
    proposer_digest text, approver_digest text, approval_expires_at timestamptz,
    source_dispatch_fencing_token bigint, created_at timestamptz, command_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
BEGIN
    -- elmpay.admin-command-db-api.v1:edge-observe
    IF session_user <> 'elmpay_edge_gateway'
       OR NULLIF(current_setting('app.tenant_id', true), '')::uuid IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'admin command observation is not authorized' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT command.command_id, command.project_id,
        command.idempotency_key::text, command.command_digest::text, command.kind,
        command.operation_code, command.consumer_group, command.target_id,
        command.proposal_digest::text, command.policy_digest::text,
        command.approval_version, command.proposer_digest::text,
        command.approver_digest::text, command.approval_expires_at,
        command.source_dispatch_fencing_token, command.created_at, command.state
      FROM admin_domain_command command
     WHERE command.tenant_id = p_tenant_id
       AND command.idempotency_key = p_idempotency_key;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_claim_command(
    p_worker_id text, p_lease_millis bigint)
RETURNS TABLE(command_id uuid, tenant_id uuid, project_id uuid, idempotency_key text,
    command_digest text, kind text, operation_code text, consumer_group text,
    target_id text, proposal_digest text, policy_digest text, approval_version bigint,
    proposer_digest text, approver_digest text, approval_expires_at timestamptz,
    source_dispatch_fencing_token bigint, created_at timestamptz, lease_until timestamptz,
    consumer_fencing_token bigint, attempt integer, previous_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_group text := CASE session_user
        WHEN 'elmpay_edge_gateway' THEN 'PAYMENT'
        WHEN 'elmpay_risk_engine' THEN 'RISK'
        WHEN 'elmpay_worker' THEN 'ROLLOUT'
        ELSE NULL END;
    v_tenant uuid;
    v_now timestamptz := clock_timestamp();
    v_lease_until timestamptz;
    v_command admin_domain_command%ROWTYPE;
    v_previous text;
    v_due timestamptz;
BEGIN
    -- elmpay.admin-command-db-api.v1:group-claim
    IF v_group IS NULL OR p_worker_id !~ '^[A-Za-z0-9._:-]{8,128}$'
       OR p_lease_millis < 5000 OR p_lease_millis > 60000 THEN
        RAISE EXCEPTION 'admin command claim is not authorized' USING ERRCODE = '42501';
    END IF;
    SELECT signal.tenant_id INTO v_tenant
      FROM admin_domain_command_signal signal
     WHERE signal.consumer_group = v_group AND signal.next_attempt_at <= v_now
       AND (signal.lease_until IS NULL OR signal.lease_until <= v_now)
     ORDER BY signal.next_attempt_at, signal.tenant_id
     FOR UPDATE SKIP LOCKED LIMIT 1;
    IF v_tenant IS NULL THEN RETURN; END IF;
    PERFORM set_config('app.tenant_id', v_tenant::text, true);
    UPDATE admin_domain_command command
       SET state = CASE WHEN command.approval_expires_at <= v_now
               THEN 'BLOCKED' ELSE 'UNKNOWN' END,
           lease_owner = NULL, lease_until = NULL,
           next_attempt_at = CASE WHEN command.approval_expires_at <= v_now
               THEN NULL ELSE v_now END,
           failure_code = CASE WHEN command.approval_expires_at <= v_now
               THEN 'APPROVAL_EXPIRED' ELSE 'STALE_LEASE' END,
           diagnostic_digest = encode(sha256(convert_to(
             (CASE WHEN command.approval_expires_at <= v_now
                THEN 'APPROVAL_EXPIRED:' ELSE 'STALE_LEASE:' END)
             || command.tenant_id || ':' || command.command_id, 'UTF8')), 'hex')
     WHERE command.tenant_id = v_tenant AND command.consumer_group = v_group
       AND command.state = 'CLAIMED' AND command.lease_until <= v_now;
    UPDATE admin_domain_command command
       SET state = 'BLOCKED', lease_owner = NULL, lease_until = NULL,
           next_attempt_at = NULL,
           failure_code = CASE WHEN command.approval_expires_at <= v_now
             THEN 'APPROVAL_EXPIRED' ELSE 'MAX_ATTEMPTS' END,
           diagnostic_digest = encode(sha256(convert_to(
             (CASE WHEN command.approval_expires_at <= v_now
               THEN 'APPROVAL_EXPIRED:' ELSE 'MAX_ATTEMPTS:' END)
             || command.tenant_id || ':' || command.command_id, 'UTF8')), 'hex')
     WHERE command.tenant_id = v_tenant AND command.consumer_group = v_group
       AND command.state IN ('PENDING','RETRY','UNKNOWN')
       AND (command.approval_expires_at <= v_now OR command.attempts >= 8);
    SELECT command.* INTO v_command
      FROM admin_domain_command command
     WHERE command.tenant_id = v_tenant AND command.consumer_group = v_group
       AND command.state IN ('PENDING','RETRY','UNKNOWN')
       AND command.next_attempt_at <= v_now AND command.approval_expires_at > v_now
       AND command.attempts < 8
       AND NOT EXISTS (SELECT 1 FROM admin_domain_command active
            WHERE active.tenant_id = v_tenant AND active.consumer_group = v_group
              AND active.state = 'CLAIMED')
     ORDER BY command.next_attempt_at, command.created_at, command.command_id
     FOR UPDATE SKIP LOCKED LIMIT 1;
    IF v_command.command_id IS NULL THEN
        SELECT COALESCE(min(command.lease_until) FILTER (WHERE command.state = 'CLAIMED'),
                        min(command.next_attempt_at) FILTER
                          (WHERE command.state IN ('PENDING','RETRY','UNKNOWN')))
          INTO v_due FROM admin_domain_command command
         WHERE command.tenant_id = v_tenant AND command.consumer_group = v_group
           AND command.state IN ('PENDING','CLAIMED','RETRY','UNKNOWN');
        IF v_due IS NULL THEN
            DELETE FROM admin_domain_command_signal signal
             WHERE signal.consumer_group = v_group AND signal.tenant_id = v_tenant;
        ELSE
            UPDATE admin_domain_command_signal signal SET next_attempt_at = v_due,
                lease_owner = NULL, lease_until = NULL
             WHERE signal.consumer_group = v_group AND signal.tenant_id = v_tenant;
        END IF;
        RETURN;
    END IF;
    v_previous := v_command.state;
    v_lease_until := v_now + (p_lease_millis * interval '1 millisecond');
    UPDATE admin_domain_command command SET state = 'CLAIMED',
           attempts = command.attempts + 1, lease_owner = p_worker_id,
           lease_until = v_lease_until, consumer_fencing_token = command.consumer_fencing_token + 1,
           next_attempt_at = NULL, failure_code = NULL, diagnostic_digest = NULL
     WHERE command.tenant_id = v_tenant AND command.command_id = v_command.command_id
     RETURNING command.* INTO STRICT v_command;
    UPDATE admin_domain_command_signal signal SET next_attempt_at = v_lease_until,
           lease_owner = p_worker_id, lease_until = v_lease_until,
           fencing_token = signal.fencing_token + 1
     WHERE signal.consumer_group = v_group AND signal.tenant_id = v_tenant;
    RETURN QUERY SELECT v_command.command_id, v_command.tenant_id, v_command.project_id,
        v_command.idempotency_key::text, v_command.command_digest::text, v_command.kind,
        v_command.operation_code, v_command.consumer_group, v_command.target_id,
        v_command.proposal_digest::text, v_command.policy_digest::text,
        v_command.approval_version, v_command.proposer_digest::text,
        v_command.approver_digest::text, v_command.approval_expires_at,
        v_command.source_dispatch_fencing_token, v_command.created_at,
        v_command.lease_until, v_command.consumer_fencing_token,
        v_command.attempts, v_previous;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_reschedule_command_signal(
    p_consumer_group text, p_tenant_id uuid) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_due timestamptz;
    v_lease_owner text;
    v_lease_until timestamptz;
BEGIN
    -- Internal-only elmpay.admin-command-db-api.v1 helper.
    SELECT COALESCE(min(command.lease_until) FILTER (WHERE command.state = 'CLAIMED'),
                    min(command.next_attempt_at) FILTER
                      (WHERE command.state IN ('PENDING','RETRY','UNKNOWN'))),
           min(command.lease_owner) FILTER (WHERE command.state = 'CLAIMED'),
           min(command.lease_until) FILTER (WHERE command.state = 'CLAIMED')
      INTO v_due, v_lease_owner, v_lease_until
      FROM admin_domain_command command
     WHERE command.tenant_id = p_tenant_id AND command.consumer_group = p_consumer_group
       AND command.state IN ('PENDING','CLAIMED','RETRY','UNKNOWN');
    IF v_due IS NULL THEN
        DELETE FROM admin_domain_command_signal signal
         WHERE signal.consumer_group = p_consumer_group AND signal.tenant_id = p_tenant_id;
    ELSE
        INSERT INTO admin_domain_command_signal
          (consumer_group, tenant_id, next_attempt_at, lease_owner, lease_until)
        VALUES (p_consumer_group, p_tenant_id, v_due, v_lease_owner, v_lease_until)
        ON CONFLICT (consumer_group, tenant_id) DO UPDATE SET
            next_attempt_at = EXCLUDED.next_attempt_at,
            lease_owner = EXCLUDED.lease_owner,
            lease_until = EXCLUDED.lease_until;
    END IF;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_complete_command(
    p_tenant_id uuid, p_command_id uuid, p_worker_id text, p_fencing_token bigint,
    p_receipt_id uuid, p_effect_digest text)
RETURNS TABLE(receipt_id uuid, tenant_id uuid, project_id uuid, idempotency_key text,
    approval_id uuid, command_digest text, kind text, operation_code text,
    consumer_group text, target_id text, proposal_digest text, policy_digest text,
    consumer_fencing_token bigint, effect_digest text, executed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_group text := CASE session_user
        WHEN 'elmpay_edge_gateway' THEN 'PAYMENT'
        WHEN 'elmpay_risk_engine' THEN 'RISK'
        WHEN 'elmpay_worker' THEN 'ROLLOUT'
        ELSE NULL END;
    v_now timestamptz := clock_timestamp();
    v_command admin_domain_command%ROWTYPE;
BEGIN
    -- elmpay.admin-command-db-api.v1:effect-commit
    IF v_group IS NULL OR NULLIF(current_setting('app.tenant_id', true), '')::uuid
           IS DISTINCT FROM p_tenant_id
       OR p_worker_id !~ '^[A-Za-z0-9._:-]{8,128}$'
       OR p_fencing_token < 1 OR p_effect_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'admin command completion is not authorized' USING ERRCODE = '42501';
    END IF;
    UPDATE admin_domain_command command
       SET state = 'APPLIED', lease_owner = NULL, lease_until = NULL,
           next_attempt_at = NULL, failure_code = NULL, diagnostic_digest = NULL
     WHERE command.tenant_id = p_tenant_id AND command.command_id = p_command_id
       AND command.consumer_group = v_group AND command.state = 'CLAIMED'
       AND command.lease_owner = p_worker_id
       AND command.consumer_fencing_token = p_fencing_token
       AND command.lease_until > v_now AND command.approval_expires_at > v_now
     RETURNING command.* INTO v_command;
    IF v_command.command_id IS NULL THEN
        RAISE EXCEPTION 'admin command completion lost its fence' USING ERRCODE = '40001';
    END IF;
    INSERT INTO admin_action_effect_receipt
      (tenant_id, project_id, receipt_id, idempotency_key, approval_id, command_digest,
       kind, operation_code, consumer_group, target_id, proposal_digest, policy_digest,
       consumer_fencing_token, effect_digest, executed_at)
    VALUES (v_command.tenant_id, v_command.project_id, p_receipt_id,
            v_command.idempotency_key, v_command.command_id, v_command.command_digest,
            v_command.kind, v_command.operation_code, v_command.consumer_group,
            v_command.target_id, v_command.proposal_digest, v_command.policy_digest,
            v_command.consumer_fencing_token, p_effect_digest, v_command.updated_at);
    PERFORM elmpay_admin_reschedule_command_signal(v_group, p_tenant_id);
    RETURN QUERY SELECT p_receipt_id, v_command.tenant_id, v_command.project_id,
        v_command.idempotency_key::text, v_command.command_id,
        v_command.command_digest::text, v_command.kind, v_command.operation_code,
        v_command.consumer_group, v_command.target_id, v_command.proposal_digest::text,
        v_command.policy_digest::text, v_command.consumer_fencing_token,
        p_effect_digest, v_command.updated_at;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_retry_command(
    p_tenant_id uuid, p_command_id uuid, p_worker_id text, p_fencing_token bigint,
    p_failure_code text, p_diagnostic_digest text, p_next_attempt_at timestamptz,
    p_outcome_unknown boolean) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_group text := CASE session_user
        WHEN 'elmpay_edge_gateway' THEN 'PAYMENT'
        WHEN 'elmpay_risk_engine' THEN 'RISK'
        WHEN 'elmpay_worker' THEN 'ROLLOUT'
        ELSE NULL END;
    v_now timestamptz := clock_timestamp();
    v_command admin_domain_command%ROWTYPE;
BEGIN
    -- elmpay.admin-command-db-api.v1:retry-or-unknown
    IF v_group IS NULL OR NULLIF(current_setting('app.tenant_id', true), '')::uuid
           IS DISTINCT FROM p_tenant_id
       OR p_worker_id !~ '^[A-Za-z0-9._:-]{8,128}$'
       OR p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
       OR p_diagnostic_digest !~ '^[0-9a-f]{64}$'
       OR p_next_attempt_at <= v_now THEN
        RAISE EXCEPTION 'admin command retry is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT command.* INTO v_command FROM admin_domain_command command
     WHERE command.tenant_id = p_tenant_id AND command.command_id = p_command_id
       AND command.consumer_group = v_group AND command.state = 'CLAIMED'
       AND command.lease_owner = p_worker_id
       AND command.consumer_fencing_token = p_fencing_token FOR UPDATE;
    IF v_command.command_id IS NULL OR v_command.lease_until <= v_now
       OR v_command.approval_expires_at <= v_now THEN
        RETURN false;
    END IF;
    IF p_next_attempt_at >= v_command.approval_expires_at THEN
        UPDATE admin_domain_command command SET state = 'BLOCKED', lease_owner = NULL,
               lease_until = NULL, next_attempt_at = NULL,
               failure_code = 'APPROVAL_EXPIRED',
               diagnostic_digest = encode(sha256(convert_to(
                 'APPROVAL_EXPIRED:' || command.tenant_id || ':' || command.command_id,
                 'UTF8')), 'hex')
         WHERE command.tenant_id = p_tenant_id AND command.command_id = p_command_id;
    ELSE
        UPDATE admin_domain_command command SET
               state = CASE WHEN p_outcome_unknown THEN 'UNKNOWN' ELSE 'RETRY' END,
               lease_owner = NULL, lease_until = NULL, next_attempt_at = p_next_attempt_at,
               failure_code = p_failure_code, diagnostic_digest = p_diagnostic_digest
         WHERE command.tenant_id = p_tenant_id AND command.command_id = p_command_id;
    END IF;
    PERFORM elmpay_admin_reschedule_command_signal(v_group, p_tenant_id);
    RETURN true;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_block_command(
    p_tenant_id uuid, p_command_id uuid, p_worker_id text, p_fencing_token bigint,
    p_failure_code text, p_diagnostic_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_group text := CASE session_user
        WHEN 'elmpay_edge_gateway' THEN 'PAYMENT'
        WHEN 'elmpay_risk_engine' THEN 'RISK'
        WHEN 'elmpay_worker' THEN 'ROLLOUT'
        ELSE NULL END;
    v_now timestamptz := clock_timestamp();
    v_changed integer;
BEGIN
    -- elmpay.admin-command-db-api.v1:block
    IF v_group IS NULL OR NULLIF(current_setting('app.tenant_id', true), '')::uuid
           IS DISTINCT FROM p_tenant_id
       OR p_worker_id !~ '^[A-Za-z0-9._:-]{8,128}$'
       OR p_failure_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
       OR p_diagnostic_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'admin command block is invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE admin_domain_command command SET state = 'BLOCKED', lease_owner = NULL,
           lease_until = NULL, next_attempt_at = NULL, failure_code = p_failure_code,
           diagnostic_digest = p_diagnostic_digest
     WHERE command.tenant_id = p_tenant_id AND command.command_id = p_command_id
       AND command.consumer_group = v_group AND command.state = 'CLAIMED'
       AND command.lease_owner = p_worker_id
       AND command.consumer_fencing_token = p_fencing_token
       AND command.lease_until > v_now AND command.approval_expires_at > v_now;
    GET DIAGNOSTICS v_changed = ROW_COUNT;
    IF v_changed = 1 THEN
        PERFORM elmpay_admin_reschedule_command_signal(v_group, p_tenant_id);
    END IF;
    RETURN v_changed = 1;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_find_effect_receipt(
    p_tenant_id uuid, p_idempotency_key text)
RETURNS TABLE(receipt_id uuid, project_id uuid, approval_id uuid, command_digest text,
    kind text, operation_code text, consumer_group text, target_id text,
    proposal_digest text, policy_digest text, consumer_fencing_token bigint,
    effect_digest text, executed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_group text := CASE session_user
        WHEN 'elmpay_risk_engine' THEN 'RISK'
        WHEN 'elmpay_worker' THEN 'ROLLOUT'
        WHEN 'elmpay_edge_gateway' THEN NULL
        ELSE '__DENIED__' END;
BEGIN
    -- elmpay.admin-command-db-api.v1:receipt-observe
    IF v_group = '__DENIED__'
       OR NULLIF(current_setting('app.tenant_id', true), '')::uuid IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'admin receipt observation is not authorized' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT receipt.receipt_id, receipt.project_id, receipt.approval_id,
        receipt.command_digest::text, receipt.kind, receipt.operation_code,
        receipt.consumer_group, receipt.target_id, receipt.proposal_digest::text,
        receipt.policy_digest::text, receipt.consumer_fencing_token,
        receipt.effect_digest::text, receipt.executed_at
      FROM admin_action_effect_receipt receipt
     WHERE receipt.tenant_id = p_tenant_id
       AND receipt.idempotency_key = p_idempotency_key
       AND (v_group IS NULL OR receipt.consumer_group = v_group);
END;
$elmpay$;

REVOKE ALL ON admin_domain_command, admin_domain_command_signal,
    admin_action_effect_receipt, admin_action_diagnostic_audit FROM PUBLIC;
REVOKE ALL ON SEQUENCE admin_action_diagnostic_audit_sequence_no_seq FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION elmpay_admin_typed_binding_guard(),
    elmpay_admin_command_transition_guard(),
    elmpay_admin_effect_receipt_guard(),
    elmpay_admin_action_immutable() FROM PUBLIC;

-- Rollback is manual: stop dispatchers/consumers, preserve append-only receipts/audit and
-- reconcile CLAIMED/UNKNOWN commands before removing policies, functions or tables.
