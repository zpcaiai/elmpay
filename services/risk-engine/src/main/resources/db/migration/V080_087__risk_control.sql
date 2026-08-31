CREATE TABLE risk_rule_set (
  tenant_id uuid NOT NULL,
  version text NOT NULL,
  rules_json jsonb NOT NULL,
  content_digest char(64) NOT NULL,
  proposer text NOT NULL,
  approver text,
  state text NOT NULL CHECK (state IN ('PROPOSED','APPROVED','ACTIVE','SUPERSEDED')),
  activate_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, version),
  UNIQUE (tenant_id, content_digest),
  CHECK (approver IS NULL OR approver <> proposer)
);
CREATE UNIQUE INDEX one_active_risk_rule_set ON risk_rule_set(tenant_id) WHERE state='ACTIVE';

CREATE TABLE risk_signal_snapshot (
  tenant_id uuid NOT NULL,
  request_id text NOT NULL,
  version text NOT NULL,
  collected_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  values_json jsonb NOT NULL,
  content_digest char(64) NOT NULL,
  PRIMARY KEY (tenant_id, request_id, version),
  CHECK (expires_at > collected_at)
);

CREATE TABLE risk_decision (
  tenant_id uuid NOT NULL,
  request_id text NOT NULL,
  request_digest char(64) NOT NULL,
  decision_id char(64) NOT NULL,
  decision_json jsonb NOT NULL,
  decided_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, request_id),
  UNIQUE (tenant_id, decision_id)
);

CREATE TABLE risk_outbox (
  event_id char(64) PRIMARY KEY,
  tenant_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type = 'risk.decision.v1'),
  payload_json jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  published_at timestamptz
);

CREATE TABLE risk_operation (
  operation_id char(64) PRIMARY KEY,
  tenant_id uuid NOT NULL,
  kind text NOT NULL,
  subject_digest char(64) NOT NULL,
  payload_json jsonb NOT NULL,
  payload_digest char(64) NOT NULL,
  proposer text NOT NULL,
  approver text,
  state text NOT NULL CHECK (state IN ('PROPOSED','APPROVED','REJECTED','EXPIRED')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  decided_at timestamptz,
  CHECK (approver IS NULL OR approver <> proposer)
);

CREATE TABLE risk_list_entry (
  tenant_id uuid NOT NULL,
  list_name text NOT NULL,
  subject_digest char(64) NOT NULL,
  active boolean NOT NULL,
  changed_by_operation char(64) NOT NULL REFERENCES risk_operation(operation_id),
  PRIMARY KEY (tenant_id, list_name, subject_digest)
);

CREATE TABLE risk_case (
  tenant_id uuid NOT NULL,
  case_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('OPEN','ASSIGNED','CLOSED')),
  subject_digest char(64) NOT NULL,
  reason text NOT NULL,
  changed_by_operation char(64) NOT NULL REFERENCES risk_operation(operation_id),
  PRIMARY KEY (tenant_id, case_id)
);

CREATE TABLE risk_audit (
  sequence_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL,
  event_type text NOT NULL,
  payload_digest char(64) NOT NULL,
  previous_hash text NOT NULL,
  audit_hash char(64) NOT NULL UNIQUE,
  occurred_at timestamptz NOT NULL
);

ALTER TABLE risk_rule_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_signal_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_operation ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_list_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_case ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_audit ENABLE ROW LEVEL SECURITY;

ALTER TABLE risk_rule_set FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_signal_snapshot FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_decision FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_operation FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_list_entry FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_case FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY risk_rules_tenant ON risk_rule_set USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_signals_tenant ON risk_signal_snapshot USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_decisions_tenant ON risk_decision USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_outbox_tenant ON risk_outbox USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_operations_tenant ON risk_operation USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_lists_tenant ON risk_list_entry USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_cases_tenant ON risk_case USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY risk_audit_tenant ON risk_audit USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
