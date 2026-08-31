-- B18/B19 admin boundary. Apply through the production migration job before admin-web starts.
-- The runtime sets elmpay.tenant_id inside every transaction; missing tenant context denies access.

CREATE TABLE IF NOT EXISTS admin_dpop_nonce (
  nonce_digest char(64) PRIMARY KEY CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > issued_at),
  CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);

CREATE TABLE IF NOT EXISTS admin_dpop_replay (
  tenant_id uuid NOT NULL,
  issuer text NOT NULL CHECK (length(issuer) BETWEEN 8 AND 512),
  subject_digest char(64) NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
  access_jti_digest char(64) NOT NULL CHECK (access_jti_digest ~ '^[0-9a-f]{64}$'),
  proof_jti_digest char(64) NOT NULL CHECK (proof_jti_digest ~ '^[0-9a-f]{64}$'),
  nonce_digest char(64) NOT NULL,
  proof_thumbprint text NOT NULL CHECK (proof_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
  seen_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (issuer, proof_jti_digest),
  UNIQUE (nonce_digest),
  CHECK (expires_at > seen_at)
);

CREATE TABLE IF NOT EXISTS admin_approval (
  approval_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('CASE_CLOSE','LIST_CHANGE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
  operation_code text NOT NULL CHECK (operation_code IN
    ('CASE_CLOSE','LIST_ADD','LIST_REMOVE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
  target_id text NOT NULL CHECK (target_id ~ '^[A-Za-z0-9._:@/-]{1,160}$'),
  proposal_digest char(64) NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
  permission text NOT NULL CHECK (permission IN ('risk_decision.override','risk_rule.write','refund.approve','config.write')),
  resource_type text NOT NULL CHECK (resource_type IN ('risk_decision','risk_rule','refund','config')),
  proposer_id text NOT NULL CHECK (length(proposer_id) BETWEEN 1 AND 160),
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  ticket_digest char(64) NOT NULL CHECK (ticket_digest ~ '^[0-9a-f]{64}$'),
  request_key_digest char(64) NOT NULL CHECK (request_key_digest ~ '^[0-9a-f]{64}$'),
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED')),
  version bigint NOT NULL CHECK (version >= 1),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  decided_by text,
  decision_reason_code text,
  decision_ticket_digest char(64),
  UNIQUE (tenant_id, request_key_digest),
  UNIQUE (tenant_id, approval_id),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
  CHECK ((kind = 'CASE_CLOSE' AND operation_code = 'CASE_CLOSE')
    OR (kind = 'LIST_CHANGE' AND operation_code IN ('LIST_ADD','LIST_REMOVE'))
    OR (kind = 'REFUND_OVERRIDE' AND operation_code = 'REFUND_OVERRIDE')
    OR (kind = 'ROLLOUT_APPROVAL' AND operation_code = 'ROLLOUT_APPROVAL')),
  CHECK ((status = 'PENDING' AND decided_at IS NULL AND decided_by IS NULL
      AND decision_reason_code IS NULL AND decision_ticket_digest IS NULL)
    OR (status IN ('APPROVED','REJECTED') AND decided_at IS NOT NULL AND decided_by IS NOT NULL
      AND decision_reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
      AND decision_ticket_digest ~ '^[0-9a-f]{64}$' AND decided_by <> proposer_id))
);

CREATE TABLE IF NOT EXISTS admin_approval_audit (
  sequence_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL,
  approval_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type IN ('PROPOSED','APPROVED','REJECTED')),
  actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 160),
  reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  ticket_digest char(64) NOT NULL CHECK (ticket_digest ~ '^[0-9a-f]{64}$'),
  previous_digest char(64) NOT NULL CHECK (previous_digest ~ '^[0-9a-f]{64}$'),
  event_digest char(64) NOT NULL UNIQUE CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL,
  UNIQUE (tenant_id, approval_id, event_type),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES admin_approval(tenant_id, approval_id)
);

CREATE TABLE IF NOT EXISTS admin_access_audit (
  sequence_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  tenant_id uuid NOT NULL,
  actor_digest char(64) NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
  event_type text NOT NULL CHECK (event_type IN ('DIAGNOSTIC_READ','APPROVAL_READ','AUTHORIZATION_DENIED')),
  resource_digest char(64) NOT NULL CHECK (resource_digest ~ '^[0-9a-f]{64}$'),
  decision text NOT NULL CHECK (decision IN ('ALLOW','DENY')),
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
  event_digest char(64) NOT NULL UNIQUE CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_diagnostic_snapshot (
  tenant_id uuid NOT NULL,
  service_name text NOT NULL CHECK (service_name ~ '^[a-z][a-z0-9-]{1,62}$'),
  safe_projection jsonb NOT NULL CHECK (jsonb_typeof(safe_projection) = 'object')
    CHECK (pg_column_size(safe_projection) <= 8192)
    CHECK ((safe_projection - ARRAY['tenantId','service','status','version','region','errorCode',
      'lastUpdated','latencyMs','traceReference','providerReference','capabilities']::text[]) = '{}'::jsonb),
  captured_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, service_name)
);

CREATE TABLE IF NOT EXISTS admin_action_dispatch (
  dispatch_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  approval_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('CASE_CLOSE','LIST_CHANGE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
  operation_code text NOT NULL CHECK (operation_code IN
    ('CASE_CLOSE','LIST_ADD','LIST_REMOVE','REFUND_OVERRIDE','ROLLOUT_APPROVAL')),
  target_id text NOT NULL CHECK (target_id ~ '^[A-Za-z0-9._:@/-]{1,160}$'),
  proposal_digest char(64) NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
  approval_version bigint NOT NULL CHECK (approval_version = 2),
  proposer_digest char(64) NOT NULL CHECK (proposer_digest ~ '^[0-9a-f]{64}$'),
  approver_digest char(64) NOT NULL CHECK (approver_digest ~ '^[0-9a-f]{64}$'),
  idempotency_key char(64) NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN ('PENDING','DISPATCHING','RETRY','UNKNOWN','BLOCKED','FAILED','SUCCEEDED')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
  receipt_poll_attempts integer NOT NULL DEFAULT 0
    CHECK (receipt_poll_attempts BETWEEN 0 AND 100000),
  outcome_unknown boolean NOT NULL DEFAULT false,
  next_attempt_at timestamptz,
  lease_owner text,
  lease_until timestamptz,
  fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
  failure_code text CHECK (failure_code IS NULL OR failure_code IN
    ('NETWORK_UNKNOWN','UPSTREAM_5XX','UPSTREAM_REJECTED','INVALID_RECEIPT','APPROVAL_MISMATCH',
     'APPROVAL_EXPIRED','MAX_ATTEMPTS')),
  receipt_digest char(64),
  receipt_id_digest char(64),
  approval_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  UNIQUE (tenant_id, approval_id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES admin_approval(tenant_id, approval_id),
  CHECK (dispatch_id = approval_id),
  CHECK (proposer_digest <> approver_digest),
  CHECK ((kind = 'CASE_CLOSE' AND operation_code = 'CASE_CLOSE')
    OR (kind = 'LIST_CHANGE' AND operation_code IN ('LIST_ADD','LIST_REMOVE'))
    OR (kind = 'REFUND_OVERRIDE' AND operation_code = 'REFUND_OVERRIDE')
    OR (kind = 'ROLLOUT_APPROVAL' AND operation_code = 'ROLLOUT_APPROVAL')),
  CHECK (created_at < approval_expires_at AND updated_at >= created_at),
  CHECK ((state = 'DISPATCHING' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
    OR (state <> 'DISPATCHING' AND lease_owner IS NULL AND lease_until IS NULL)),
  CHECK ((state IN ('PENDING','RETRY','UNKNOWN') AND next_attempt_at IS NOT NULL)
    OR (state NOT IN ('PENDING','RETRY','UNKNOWN') AND next_attempt_at IS NULL)),
  CHECK ((state IN ('PENDING','DISPATCHING','SUCCEEDED') AND failure_code IS NULL)
    OR (state = 'RETRY' AND failure_code = 'UPSTREAM_5XX')
    OR (state = 'UNKNOWN' AND failure_code = 'NETWORK_UNKNOWN')
    OR (state = 'BLOCKED' AND failure_code IN ('UPSTREAM_REJECTED','INVALID_RECEIPT','APPROVAL_MISMATCH'))
    OR (state = 'FAILED' AND failure_code IN ('APPROVAL_EXPIRED','MAX_ATTEMPTS'))),
  CHECK ((state = 'SUCCEEDED' AND receipt_digest ~ '^[0-9a-f]{64}$'
      AND receipt_id_digest ~ '^[0-9a-f]{64}$' AND failure_code IS NULL)
    OR (state <> 'SUCCEEDED' AND receipt_digest IS NULL AND receipt_id_digest IS NULL))
);

-- Contains only a tenant UUID and scheduling metadata. It is the least-privilege cross-tenant
-- wake-up index; dispatch payloads remain FORCE-RLS tenant rows.
CREATE TABLE IF NOT EXISTS admin_dispatch_signal (
  tenant_id uuid PRIMARY KEY,
  next_attempt_at timestamptz NOT NULL,
  lease_owner text,
  lease_until timestamptz,
  fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
  CHECK ((lease_owner IS NULL AND lease_until IS NULL) OR (lease_owner IS NOT NULL AND lease_until IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS admin_dpop_nonce_expiry_idx ON admin_dpop_nonce(expires_at);
CREATE INDEX IF NOT EXISTS admin_dpop_replay_expiry_idx ON admin_dpop_replay(tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS admin_action_dispatch_due_idx
  ON admin_action_dispatch(tenant_id, next_attempt_at) WHERE state IN ('PENDING','RETRY','UNKNOWN','DISPATCHING');
CREATE INDEX IF NOT EXISTS admin_dispatch_signal_due_idx ON admin_dispatch_signal(next_attempt_at);

CREATE OR REPLACE FUNCTION elmpay_admin_approval_transition_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'admin approvals cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.approval_id <> OLD.approval_id OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.project_id <> OLD.project_id OR NEW.kind <> OLD.kind
     OR NEW.operation_code <> OLD.operation_code OR NEW.target_id <> OLD.target_id
     OR NEW.proposal_digest <> OLD.proposal_digest OR NEW.permission <> OLD.permission
     OR NEW.resource_type <> OLD.resource_type OR NEW.proposer_id <> OLD.proposer_id
     OR NEW.reason_code <> OLD.reason_code OR NEW.ticket_digest <> OLD.ticket_digest
     OR NEW.request_key_digest <> OLD.request_key_digest OR NEW.policy_digest <> OLD.policy_digest
     OR NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at
     OR OLD.status <> 'PENDING' OR NEW.status NOT IN ('APPROVED','REJECTED')
     OR NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'invalid immutable admin approval transition' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION elmpay_admin_immutable_history() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'admin security history is append only' USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION elmpay_admin_replay_retention_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'UPDATE' OR OLD.expires_at >= clock_timestamp() - interval '5 minutes' THEN
    RAISE EXCEPTION 'live admin replay state is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION elmpay_admin_dispatch_transition_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'admin action dispatches cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.dispatch_id <> OLD.dispatch_id OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.project_id <> OLD.project_id OR NEW.approval_id <> OLD.approval_id
     OR NEW.kind <> OLD.kind OR NEW.operation_code <> OLD.operation_code
     OR NEW.target_id <> OLD.target_id OR NEW.proposal_digest <> OLD.proposal_digest
     OR NEW.policy_digest <> OLD.policy_digest OR NEW.approval_version <> OLD.approval_version
     OR NEW.proposer_digest <> OLD.proposer_digest OR NEW.approver_digest <> OLD.approver_digest
     OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.approval_expires_at <> OLD.approval_expires_at
     OR NEW.created_at <> OLD.created_at OR NEW.updated_at < OLD.updated_at
     OR NEW.attempts <> OLD.attempts + CASE WHEN NEW.state = 'DISPATCHING'
       AND NOT OLD.outcome_unknown AND OLD.state <> 'DISPATCHING' THEN 1 ELSE 0 END
     OR NEW.receipt_poll_attempts <> OLD.receipt_poll_attempts
       + CASE WHEN NEW.state = 'DISPATCHING'
         AND (OLD.outcome_unknown OR OLD.state = 'DISPATCHING') THEN 1 ELSE 0 END
     OR NOT (NEW.outcome_unknown = OLD.outcome_unknown
       OR (NOT OLD.outcome_unknown AND NEW.outcome_unknown
         AND (NEW.state = 'UNKNOWN' OR (OLD.state = 'DISPATCHING'
           AND NEW.state = 'DISPATCHING' AND OLD.lease_until <= clock_timestamp()))))
     OR NEW.fencing_token <> OLD.fencing_token + CASE WHEN NEW.state = 'DISPATCHING' THEN 1 ELSE 0 END
     OR NOT ((OLD.state IN ('PENDING','RETRY','UNKNOWN') AND NEW.state IN ('DISPATCHING','BLOCKED','FAILED'))
       OR (OLD.state = 'DISPATCHING' AND NEW.state IN
         ('DISPATCHING','RETRY','UNKNOWN','BLOCKED','FAILED','SUCCEEDED'))) THEN
    RAISE EXCEPTION 'invalid immutable admin dispatch transition' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS admin_approval_transition_guard ON admin_approval;
CREATE TRIGGER admin_approval_transition_guard BEFORE UPDATE OR DELETE ON admin_approval
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_approval_transition_guard();
DROP TRIGGER IF EXISTS admin_approval_audit_immutable ON admin_approval_audit;
CREATE TRIGGER admin_approval_audit_immutable BEFORE UPDATE OR DELETE ON admin_approval_audit
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_immutable_history();
DROP TRIGGER IF EXISTS admin_access_audit_immutable ON admin_access_audit;
CREATE TRIGGER admin_access_audit_immutable BEFORE UPDATE OR DELETE ON admin_access_audit
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_immutable_history();
DROP TRIGGER IF EXISTS admin_dpop_replay_immutable ON admin_dpop_replay;
CREATE TRIGGER admin_dpop_replay_immutable BEFORE UPDATE OR DELETE ON admin_dpop_replay
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_replay_retention_guard();
DROP TRIGGER IF EXISTS admin_action_dispatch_transition_guard ON admin_action_dispatch;
CREATE TRIGGER admin_action_dispatch_transition_guard BEFORE UPDATE OR DELETE ON admin_action_dispatch
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_dispatch_transition_guard();

ALTER TABLE admin_dpop_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_dpop_replay FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_approval FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_approval_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_approval_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_access_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_access_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_diagnostic_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_diagnostic_snapshot FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_action_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_dispatch FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS admin_dpop_replay_tenant ON admin_dpop_replay;
CREATE POLICY admin_dpop_replay_tenant ON admin_dpop_replay
USING (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_approval_tenant ON admin_approval;
CREATE POLICY admin_approval_tenant ON admin_approval
USING (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_approval_audit_tenant ON admin_approval_audit;
CREATE POLICY admin_approval_audit_tenant ON admin_approval_audit
USING (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_access_audit_tenant ON admin_access_audit;
CREATE POLICY admin_access_audit_tenant ON admin_access_audit
USING (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_diagnostic_snapshot_tenant ON admin_diagnostic_snapshot;
CREATE POLICY admin_diagnostic_snapshot_tenant ON admin_diagnostic_snapshot
USING (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_action_dispatch_tenant ON admin_action_dispatch;
CREATE POLICY admin_action_dispatch_tenant ON admin_action_dispatch
USING (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('elmpay.tenant_id', true), '')::uuid);

REVOKE ALL ON admin_dpop_nonce, admin_dpop_replay, admin_approval, admin_approval_audit,
  admin_access_audit, admin_diagnostic_snapshot, admin_action_dispatch, admin_dispatch_signal FROM PUBLIC;
REVOKE ALL ON SEQUENCE admin_approval_audit_sequence_no_seq, admin_access_audit_sequence_no_seq FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION elmpay_admin_approval_transition_guard(),
  elmpay_admin_immutable_history(), elmpay_admin_replay_retention_guard(),
  elmpay_admin_dispatch_transition_guard() FROM PUBLIC;

-- Rollback is intentionally manual: stop admin-web, export immutable audit/replay evidence,
-- then drop policies, triggers, functions and tables in reverse dependency order.
