-- B24 durable tenant/project registry. This is independent of payment transaction tables.
CREATE TABLE IF NOT EXISTS tenant_registry (
    id uuid PRIMARY KEY,
    external_reference text NOT NULL UNIQUE,
    code text NOT NULL UNIQUE CHECK (code ~ '^[a-z][a-z0-9_-]{1,63}$'),
    state text NOT NULL CHECK (state IN
        ('DRAFT', 'ACTIVE', 'SUSPENDED', 'OFFBOARDING', 'CLOSED')),
    last_transition_evidence_flags text[] NOT NULL DEFAULT ARRAY[]::text[],
    last_transition_actor_id text,
    last_transition_second_approver_id text,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at)
);

CREATE TABLE IF NOT EXISTS project_registry (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenant_registry(id),
    code text NOT NULL CHECK (code ~ '^[a-z][a-z0-9_-]{1,63}$'),
    environment text NOT NULL CHECK (environment IN ('test', 'live')),
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, code, environment)
);

CREATE TABLE IF NOT EXISTS project_quota (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    quota_kind text NOT NULL CHECK (quota_kind IN
        ('PAYMENTS_PER_MINUTE', 'API_KEYS_PER_ENVIRONMENT',
         'WEBHOOK_ENDPOINTS_PER_PROJECT')),
    environment text NOT NULL CHECK (environment IN ('all', 'test', 'live')),
    limit_value bigint NOT NULL CHECK (limit_value > 0),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, quota_kind, environment),
    FOREIGN KEY (tenant_id, project_id) REFERENCES project_registry(tenant_id, id),
    CHECK ((quota_kind = 'API_KEYS_PER_ENVIRONMENT' AND environment IS NOT NULL
            AND limit_value <= 50)
        OR (quota_kind = 'PAYMENTS_PER_MINUTE' AND environment = 'all'
            AND limit_value <= 60000)
        OR (quota_kind = 'WEBHOOK_ENDPOINTS_PER_PROJECT' AND environment = 'all'
            AND limit_value <= 20))
);

CREATE TABLE IF NOT EXISTS merchant_control_audit (
    sequence_no bigserial PRIMARY KEY,
    id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL REFERENCES tenant_registry(id),
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    actor_id text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    evidence_flags text[] NOT NULL DEFAULT ARRAY[]::text[],
    second_approver_id text,
    occurred_at timestamptz NOT NULL
);

CREATE OR REPLACE FUNCTION elmpay_validate_tenant_registry_transition()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.version <> OLD.version + 1 OR NEW.id <> OLD.id
     OR NEW.external_reference <> OLD.external_reference OR NEW.code <> OLD.code THEN
    RAISE EXCEPTION 'tenant identity is immutable and version must advance exactly once';
  END IF;
  IF NOT ((OLD.state = 'DRAFT' AND NEW.state = 'ACTIVE')
      OR (OLD.state = 'ACTIVE' AND NEW.state IN ('SUSPENDED', 'OFFBOARDING'))
      OR (OLD.state = 'SUSPENDED' AND NEW.state IN ('ACTIVE', 'OFFBOARDING'))
      OR (OLD.state = 'OFFBOARDING' AND NEW.state = 'CLOSED')) THEN
    RAISE EXCEPTION 'illegal tenant lifecycle transition: % -> %', OLD.state, NEW.state;
  END IF;
  IF OLD.state = 'DRAFT' AND NEW.state = 'ACTIVE'
     AND NOT (NEW.last_transition_evidence_flags @> ARRAY['kyb_verified', 'contract_signed']) THEN
    RAISE EXCEPTION 'tenant activation requires KYB and signed contract';
  END IF;
  IF (NEW.state = 'OFFBOARDING'
      OR (OLD.state = 'SUSPENDED' AND NEW.state = 'ACTIVE'))
     AND (NEW.last_transition_second_approver_id IS NULL
          OR NEW.last_transition_second_approver_id = NEW.last_transition_actor_id) THEN
    RAISE EXCEPTION 'tenant transition requires a distinct second approver';
  END IF;
  IF OLD.state = 'OFFBOARDING' AND NEW.state = 'CLOSED'
     AND NOT (NEW.last_transition_evidence_flags @>
              ARRAY['settlement_complete', 'retention_period_started', 'kek_destroyed']) THEN
    RAISE EXCEPTION 'tenant closure prerequisites are incomplete';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS tenant_registry_transition_guard ON tenant_registry;
CREATE TRIGGER tenant_registry_transition_guard
BEFORE UPDATE ON tenant_registry
FOR EACH ROW EXECUTE FUNCTION elmpay_validate_tenant_registry_transition();

CREATE OR REPLACE FUNCTION elmpay_reject_merchant_control_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'merchant control audit is append only';
END $$;

DROP TRIGGER IF EXISTS merchant_control_audit_immutable ON merchant_control_audit;
CREATE TRIGGER merchant_control_audit_immutable
BEFORE UPDATE OR DELETE ON merchant_control_audit
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_merchant_control_audit_mutation();

ALTER TABLE tenant_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE project_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE project_quota ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_quota FORCE ROW LEVEL SECURITY;
ALTER TABLE merchant_control_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_control_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_registry_self_policy ON tenant_registry;
CREATE POLICY tenant_registry_self_policy ON tenant_registry
    USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS project_registry_tenant_policy ON project_registry;
CREATE POLICY project_registry_tenant_policy ON project_registry
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS project_quota_tenant_policy ON project_quota;
CREATE POLICY project_quota_tenant_policy ON project_quota
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS merchant_control_audit_tenant_policy ON merchant_control_audit;
CREATE POLICY merchant_control_audit_tenant_policy ON merchant_control_audit
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON merchant_control_audit FROM PUBLIC;

-- Rollback: drop policies/triggers and the four registry tables after dependent batches.
