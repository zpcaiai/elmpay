-- Additive hardening for the durable cross-domain admin command queue.
-- This migration intentionally follows V087_1, V102 and V087_2. Runtime identities receive
-- only narrow SECURITY DEFINER capabilities and never direct queue-table DML.

-- Contract migration gate: old direct-DML consumers must be drained before any DDL or revoke.
-- The release controller must stop edge/risk/worker workloads, wait for their database sessions
-- to close, run this migration, then start the function-only binaries. This is an explicit
-- maintenance-mode upgrade, not a zero-downtime expand/contract claim.
DO $elmpay$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_stat_activity activity
         WHERE activity.pid <> pg_backend_pid()
           AND activity.datname = current_database()
           AND activity.usename IN
             ('elmpay_edge_gateway','elmpay_risk_engine','elmpay_worker')
    ) THEN
        RAISE EXCEPTION 'V103 requires drained edge/risk/worker database sessions'
            USING ERRCODE = '55000';
    END IF;
END;
$elmpay$;

DO $elmpay$
DECLARE
    constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT constraint.conname
          FROM pg_constraint constraint
          JOIN pg_attribute attribute
            ON attribute.attrelid = constraint.conrelid
           AND attribute.attnum = constraint.conkey[1]
         WHERE constraint.conrelid = 'public.admin_domain_command'::regclass
           AND constraint.contype = 'u' AND cardinality(constraint.conkey) = 1
           AND attribute.attname = 'idempotency_key'
    LOOP
        EXECUTE format('ALTER TABLE public.admin_domain_command DROP CONSTRAINT %I',
                       constraint_name);
    END LOOP;
    FOR constraint_name IN
        SELECT constraint.conname
          FROM pg_constraint constraint
          JOIN pg_attribute attribute
            ON attribute.attrelid = constraint.conrelid
           AND attribute.attnum = constraint.conkey[1]
         WHERE constraint.conrelid = 'public.admin_action_effect_receipt'::regclass
           AND constraint.contype = 'u' AND cardinality(constraint.conkey) = 1
           AND attribute.attname = 'idempotency_key'
    LOOP
        EXECUTE format('ALTER TABLE public.admin_action_effect_receipt DROP CONSTRAINT %I',
                       constraint_name);
    END LOOP;
END;
$elmpay$;

ALTER TABLE admin_domain_command
    DROP CONSTRAINT IF EXISTS admin_domain_command_exact_receipt_binding_key;
ALTER TABLE admin_domain_command
    ADD CONSTRAINT admin_domain_command_exact_receipt_binding_key UNIQUE
      (tenant_id, command_id, project_id, idempotency_key, command_digest, kind,
       operation_code, consumer_group, target_id, proposal_digest, policy_digest);
ALTER TABLE admin_action_effect_receipt
    DROP CONSTRAINT IF EXISTS admin_action_effect_receipt_exact_command_fk;
DO $elmpay$
DECLARE
    constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT constraint.conname
          FROM pg_constraint constraint
         WHERE constraint.conrelid = 'public.admin_action_effect_receipt'::regclass
           AND constraint.confrelid = 'public.admin_domain_command'::regclass
           AND constraint.contype = 'f'
    LOOP
        EXECUTE format('ALTER TABLE public.admin_action_effect_receipt DROP CONSTRAINT %I',
                       constraint_name);
    END LOOP;
END;
$elmpay$;
ALTER TABLE admin_action_effect_receipt
    ADD CONSTRAINT admin_action_effect_receipt_exact_command_fk
    FOREIGN KEY (tenant_id, approval_id, project_id, idempotency_key, command_digest,
                 kind, operation_code, consumer_group, target_id, proposal_digest,
                 policy_digest)
    REFERENCES admin_domain_command
      (tenant_id, command_id, project_id, idempotency_key, command_digest,
       kind, operation_code, consumer_group, target_id, proposal_digest, policy_digest);

ALTER TABLE admin_domain_command
    DROP CONSTRAINT IF EXISTS admin_domain_command_rollout_effect_binding_key;
ALTER TABLE admin_domain_command
    ADD CONSTRAINT admin_domain_command_rollout_effect_binding_key UNIQUE
      (tenant_id, command_id, project_id, idempotency_key, command_digest, kind,
       operation_code, consumer_group, target_id, proposal_digest, policy_digest,
       proposer_digest, approver_digest, consumer_fencing_token);
ALTER TABLE admin_rollout_stage_approval
    ADD COLUMN IF NOT EXISTS idempotency_key char(64),
    ADD COLUMN IF NOT EXISTS command_digest char(64),
    ADD COLUMN IF NOT EXISTS kind text,
    ADD COLUMN IF NOT EXISTS operation_code text,
    ADD COLUMN IF NOT EXISTS consumer_group text,
    ADD COLUMN IF NOT EXISTS target_id text,
    ADD COLUMN IF NOT EXISTS consumer_fencing_token bigint;
UPDATE admin_rollout_stage_approval approval
   SET idempotency_key = command.idempotency_key,
       command_digest = command.command_digest,
       kind = command.kind,
       operation_code = command.operation_code,
       consumer_group = command.consumer_group,
       target_id = command.target_id,
       consumer_fencing_token = command.consumer_fencing_token
  FROM admin_domain_command command
 WHERE approval.tenant_id = command.tenant_id
   AND approval.command_id = command.command_id
   AND approval.project_id = command.project_id
   AND approval.stage_proposal_digest = command.proposal_digest
   AND approval.policy_digest = command.policy_digest
   AND approval.proposer_digest = command.proposer_digest
   AND approval.approver_digest = command.approver_digest
   AND command.kind = 'ROLLOUT_APPROVAL'
   AND command.operation_code = 'ROLLOUT_APPROVAL'
   AND command.consumer_group = 'ROLLOUT'
   AND command.target_id = approval.rollout_id::text
   AND approval.idempotency_key IS NULL;
DO $elmpay$
BEGIN
    IF EXISTS (SELECT 1 FROM admin_rollout_stage_approval
                WHERE idempotency_key IS NULL OR command_digest IS NULL
                   OR kind IS NULL OR operation_code IS NULL OR consumer_group IS NULL
                   OR target_id IS NULL OR consumer_fencing_token IS NULL) THEN
        RAISE EXCEPTION 'legacy rollout approval cannot be bound to an exact admin command'
            USING ERRCODE = '55000';
    END IF;
END;
$elmpay$;
ALTER TABLE admin_rollout_stage_approval
    ALTER COLUMN idempotency_key SET NOT NULL,
    ALTER COLUMN command_digest SET NOT NULL,
    ALTER COLUMN kind SET NOT NULL,
    ALTER COLUMN operation_code SET NOT NULL,
    ALTER COLUMN consumer_group SET NOT NULL,
    ALTER COLUMN target_id SET NOT NULL,
    ALTER COLUMN consumer_fencing_token SET NOT NULL;
ALTER TABLE admin_rollout_stage_approval
    DROP CONSTRAINT IF EXISTS admin_rollout_stage_approval_exact_command_fk;
ALTER TABLE admin_rollout_stage_approval
    ADD CONSTRAINT admin_rollout_stage_approval_exact_command_fk
    FOREIGN KEY (tenant_id, command_id, project_id, idempotency_key, command_digest,
                 kind, operation_code, consumer_group, target_id,
                 stage_proposal_digest, policy_digest, proposer_digest, approver_digest,
                 consumer_fencing_token)
    REFERENCES admin_domain_command
      (tenant_id, command_id, project_id, idempotency_key, command_digest, kind,
       operation_code, consumer_group, target_id, proposal_digest, policy_digest,
       proposer_digest, approver_digest, consumer_fencing_token);

-- One tenant context key is authoritative across admin, risk, payment, and rollout tables.
DROP POLICY IF EXISTS admin_dpop_replay_tenant ON admin_dpop_replay;
CREATE POLICY admin_dpop_replay_tenant ON admin_dpop_replay
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_approval_tenant ON admin_approval;
CREATE POLICY admin_approval_tenant ON admin_approval
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_approval_audit_tenant ON admin_approval_audit;
CREATE POLICY admin_approval_audit_tenant ON admin_approval_audit
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_access_audit_tenant ON admin_access_audit;
CREATE POLICY admin_access_audit_tenant ON admin_access_audit
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_diagnostic_snapshot_tenant ON admin_diagnostic_snapshot;
CREATE POLICY admin_diagnostic_snapshot_tenant ON admin_diagnostic_snapshot
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_action_dispatch_tenant ON admin_action_dispatch;
CREATE POLICY admin_action_dispatch_tenant ON admin_action_dispatch
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

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
       OR v_command.approval_expires_at <> p_approval_expires_at
       OR v_command.source_dispatch_fencing_token <>
            p_source_dispatch_fencing_token THEN
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
        WHEN 'elmpay_edge_gateway' THEN 'PAYMENT'
        ELSE NULL END;
BEGIN
    -- elmpay.admin-command-db-api.v1:owned-receipt-reconcile
    IF v_group IS NULL
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
       AND receipt.consumer_group = v_group;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_admin_observe_effect_receipt(
    p_tenant_id uuid, p_project_id uuid, p_idempotency_key text, p_command_id uuid,
    p_command_digest text, p_kind text, p_operation_code text, p_consumer_group text,
    p_target_id text, p_proposal_digest text, p_policy_digest text,
    p_approval_version bigint, p_proposer_digest text, p_approver_digest text,
    p_approval_expires_at timestamptz, p_source_dispatch_fencing_token bigint)
RETURNS TABLE(receipt_id uuid, project_id uuid, approval_id uuid, command_digest text,
    kind text, operation_code text, consumer_group text, target_id text,
    proposal_digest text, policy_digest text, consumer_fencing_token bigint,
    effect_digest text, executed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
BEGIN
    -- elmpay.admin-command-db-api.v1:edge-exact-envelope-receipt-observe
    IF session_user <> 'elmpay_edge_gateway'
       OR NULLIF(current_setting('app.tenant_id', true), '')::uuid IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'admin cross-group receipt observation is not authorized'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT receipt.receipt_id, receipt.project_id, receipt.approval_id,
        receipt.command_digest::text, receipt.kind, receipt.operation_code,
        receipt.consumer_group, receipt.target_id, receipt.proposal_digest::text,
        receipt.policy_digest::text, receipt.consumer_fencing_token,
        receipt.effect_digest::text, receipt.executed_at
      FROM admin_domain_command command
      JOIN admin_action_effect_receipt receipt
        ON receipt.tenant_id = command.tenant_id
       AND receipt.approval_id = command.command_id
       AND receipt.project_id = command.project_id
       AND receipt.idempotency_key = command.idempotency_key
       AND receipt.command_digest = command.command_digest
       AND receipt.kind = command.kind AND receipt.operation_code = command.operation_code
       AND receipt.consumer_group = command.consumer_group
       AND receipt.target_id = command.target_id
       AND receipt.proposal_digest = command.proposal_digest
       AND receipt.policy_digest = command.policy_digest
       AND receipt.consumer_fencing_token = command.consumer_fencing_token
     WHERE command.tenant_id = p_tenant_id AND command.project_id = p_project_id
       AND command.idempotency_key = p_idempotency_key
       AND command.command_id = p_command_id AND command.command_digest = p_command_digest
       AND command.kind = p_kind AND command.operation_code = p_operation_code
       AND command.consumer_group = p_consumer_group AND command.target_id = p_target_id
       AND command.proposal_digest = p_proposal_digest
       AND command.policy_digest = p_policy_digest
       AND command.approval_version = p_approval_version
       AND command.proposer_digest = p_proposer_digest
       AND command.approver_digest = p_approver_digest
       AND command.approval_expires_at = p_approval_expires_at
       AND command.source_dispatch_fencing_token = p_source_dispatch_fencing_token
       AND command.state = 'APPLIED' AND command.updated_at = receipt.executed_at;
END;
$elmpay$;

REVOKE ALL ON admin_domain_command, admin_domain_command_signal,
    admin_action_effect_receipt, admin_action_diagnostic_audit FROM PUBLIC;
REVOKE ALL ON SEQUENCE admin_action_diagnostic_audit_sequence_no_seq FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION elmpay_admin_typed_binding_guard(),
    elmpay_admin_command_transition_guard(),
    elmpay_admin_effect_receipt_guard(),
    elmpay_admin_action_immutable() FROM PUBLIC;

CREATE OR REPLACE FUNCTION elmpay_apply_admin_rollout_approval(
    p_tenant_id uuid, p_command_id uuid, p_worker_id text,
    p_consumer_fencing_token bigint, p_approval_record_id uuid)
RETURNS TABLE(rollout_id uuid, project_id uuid, release_binding_digest text,
    target_digest text, provider_id text, region text, artifact_digest text,
    previous_artifact_digest text, stage_index integer, stage_started_at timestamptz,
    stage_proposal_digest text, rollout_status text, rollout_fencing_token bigint,
    recorded_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public SET row_security = on AS $elmpay$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_command admin_domain_command%ROWTYPE;
    v_rollout rollout_execution%ROWTYPE;
    v_rollout_id uuid;
BEGIN
    -- elmpay.admin-command-db-api.v1:rollout-owner-effect
    IF session_user <> 'elmpay_worker'
       OR NULLIF(current_setting('app.tenant_id', true), '')::uuid
            IS DISTINCT FROM p_tenant_id
       OR p_worker_id !~ '^[A-Za-z0-9._:-]{8,128}$'
       OR p_consumer_fencing_token < 1 THEN
        RAISE EXCEPTION 'rollout admin effect is not authorized' USING ERRCODE = '42501';
    END IF;
    SELECT command.* INTO v_command FROM admin_domain_command command
     WHERE command.tenant_id = p_tenant_id AND command.command_id = p_command_id
       AND command.kind = 'ROLLOUT_APPROVAL'
       AND command.operation_code = 'ROLLOUT_APPROVAL'
       AND command.consumer_group = 'ROLLOUT' AND command.state = 'CLAIMED'
       AND command.lease_owner = p_worker_id
       AND command.consumer_fencing_token = p_consumer_fencing_token
       AND command.lease_until > v_now AND command.approval_expires_at > v_now
     FOR UPDATE;
    IF v_command.command_id IS NULL
       OR v_command.target_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
        RAISE EXCEPTION 'rollout admin command lost its exact fence' USING ERRCODE = '40001';
    END IF;
    v_rollout_id := v_command.target_id::uuid;
    SELECT rollout.* INTO v_rollout FROM rollout_execution rollout
     WHERE rollout.tenant_id = p_tenant_id AND rollout.rollout_id = v_rollout_id
     FOR UPDATE;
    IF v_rollout.rollout_id IS NULL OR v_rollout.project_id <> v_command.project_id
       OR v_rollout.stage_proposal_digest <> v_command.proposal_digest
       OR v_rollout.status <> 'RUNNING' OR v_rollout.fencing_token < 1
       OR v_rollout.stage_index < 0 THEN
        RAISE EXCEPTION 'rollout target does not match the approved immutable stage'
            USING ERRCODE = '55000';
    END IF;
    INSERT INTO admin_rollout_stage_approval
      (tenant_id, project_id, approval_record_id, command_id, rollout_id, stage_index,
       stage_proposal_digest, policy_digest, proposer_digest, approver_digest,
       rollout_fencing_token, recorded_at, idempotency_key, command_digest, kind,
       operation_code, consumer_group, target_id, consumer_fencing_token)
    VALUES (v_command.tenant_id, v_command.project_id, p_approval_record_id,
            v_command.command_id, v_rollout.rollout_id, v_rollout.stage_index,
            v_command.proposal_digest, v_command.policy_digest, v_command.proposer_digest,
            v_command.approver_digest, v_rollout.fencing_token, v_now,
            v_command.idempotency_key, v_command.command_digest, v_command.kind,
            v_command.operation_code, v_command.consumer_group, v_command.target_id,
            v_command.consumer_fencing_token);
    RETURN QUERY SELECT v_rollout.rollout_id, v_rollout.project_id,
        v_rollout.release_binding_digest::text, v_rollout.target_digest::text,
        v_rollout.provider_id, v_rollout.region, v_rollout.artifact_digest::text,
        v_rollout.previous_artifact_digest::text, v_rollout.stage_index,
        v_rollout.stage_started_at, v_rollout.stage_proposal_digest::text,
        v_rollout.status, v_rollout.fencing_token, v_now;
END;
$elmpay$;

-- Runtime identities have no direct queue-table capability. Later baseline migrations may have
-- granted it, so this additive migration revokes all such access after every dependency exists.
REVOKE ALL ON admin_domain_command, admin_domain_command_signal,
    admin_action_effect_receipt FROM elmpay_edge_gateway, elmpay_risk_engine, elmpay_worker;
REVOKE ALL ON rollout_execution, admin_rollout_stage_approval FROM elmpay_worker;

ALTER FUNCTION elmpay_admin_enqueue_command(uuid,uuid,uuid,text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint)
    OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_observe_command(uuid,text) OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_claim_command(text,bigint) OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_reschedule_command_signal(text,uuid) OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_complete_command(uuid,uuid,text,bigint,uuid,text)
    OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_retry_command(uuid,uuid,text,bigint,text,text,timestamptz,boolean)
    OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_block_command(uuid,uuid,text,bigint,text,text)
    OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_find_effect_receipt(uuid,text) OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_admin_observe_effect_receipt(uuid,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint)
    OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_apply_admin_rollout_approval(uuid,uuid,text,bigint,uuid)
    OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_resolve_webhook_ingress_endpoint(text) OWNER TO elmpay_migrator;
ALTER FUNCTION elmpay_active_worker_scopes(uuid,uuid,integer) OWNER TO elmpay_migrator;

REVOKE ALL ON FUNCTION
    elmpay_admin_enqueue_command(uuid,uuid,uuid,text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint),
    elmpay_admin_observe_command(uuid,text),
    elmpay_admin_claim_command(text,bigint),
    elmpay_admin_reschedule_command_signal(text,uuid),
    elmpay_admin_complete_command(uuid,uuid,text,bigint,uuid,text),
    elmpay_admin_retry_command(uuid,uuid,text,bigint,text,text,timestamptz,boolean),
    elmpay_admin_block_command(uuid,uuid,text,bigint,text,text),
    elmpay_admin_find_effect_receipt(uuid,text),
    elmpay_admin_observe_effect_receipt(uuid,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint),
    elmpay_apply_admin_rollout_approval(uuid,uuid,text,bigint,uuid)
FROM PUBLIC, elmpay_edge_gateway, elmpay_risk_engine, elmpay_worker;

GRANT EXECUTE ON FUNCTION
    elmpay_admin_enqueue_command(uuid,uuid,uuid,text,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint),
    elmpay_admin_observe_command(uuid,text)
TO elmpay_edge_gateway;
GRANT EXECUTE ON FUNCTION
    elmpay_admin_claim_command(text,bigint),
    elmpay_admin_complete_command(uuid,uuid,text,bigint,uuid,text),
    elmpay_admin_retry_command(uuid,uuid,text,bigint,text,text,timestamptz,boolean),
    elmpay_admin_block_command(uuid,uuid,text,bigint,text,text),
    elmpay_admin_find_effect_receipt(uuid,text)
TO elmpay_edge_gateway, elmpay_risk_engine, elmpay_worker;
GRANT EXECUTE ON FUNCTION
    elmpay_admin_observe_effect_receipt(uuid,uuid,text,uuid,text,text,text,text,text,text,text,bigint,text,text,timestamptz,bigint)
TO elmpay_edge_gateway;
GRANT EXECUTE ON FUNCTION
    elmpay_apply_admin_rollout_approval(uuid,uuid,text,bigint,uuid)
TO elmpay_worker;
REVOKE ALL ON FUNCTION elmpay_resolve_webhook_ingress_endpoint(text),
    elmpay_active_worker_scopes(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION elmpay_resolve_webhook_ingress_endpoint(text)
TO elmpay_edge_gateway;
GRANT EXECUTE ON FUNCTION elmpay_active_worker_scopes(uuid,uuid,integer)
TO elmpay_worker;

REVOKE ALL ON FUNCTION
    risk_runtime_forbid_change(),
    risk_runtime_protect_rule_set(),
    risk_runtime_protect_operation(),
    risk_runtime_protect_nonce(),
    risk_runtime_validate_list_effect(),
    risk_runtime_validate_case_effect(),
    elmpay_admin_rollout_approval_immutable()
FROM PUBLIC;

-- Rollback is manual and requires draining consumers, reconciling UNKNOWN commands, and
-- preserving immutable effect receipts before restoring any direct role grants.
