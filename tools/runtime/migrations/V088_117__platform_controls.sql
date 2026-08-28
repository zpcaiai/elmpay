CREATE TABLE edge_nonce (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  nonce text NOT NULL,
  request_digest char(64) NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, project_id, nonce)
);
CREATE INDEX edge_nonce_expiry ON edge_nonce(expires_at);

CREATE TABLE edge_quota (
  tenant_id uuid NOT NULL,
  scope_digest char(64) NOT NULL,
  bucket bigint NOT NULL,
  used bigint NOT NULL CHECK (used >= 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, scope_digest, bucket)
);
CREATE INDEX edge_quota_expiry ON edge_quota(expires_at);

CREATE TABLE resource_fence (
  tenant_id uuid NOT NULL,
  resource text NOT NULL,
  holder text NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, resource)
);

CREATE TABLE region_epoch (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  active_region text NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token > 0),
  changed_at timestamptz NOT NULL,
  request_digest char(64) NOT NULL
);

CREATE TABLE provider_health (
  tenant_id uuid NOT NULL,
  provider_account_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('HEALTHY','DEGRADED','OPEN','HALF_OPEN','UNKNOWN')),
  open_until timestamptz,
  half_open_used integer NOT NULL DEFAULT 0 CHECK (half_open_used >= 0),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, provider_account_id)
);

CREATE TABLE provider_outcome (
  tenant_id uuid NOT NULL,
  provider_account_id uuid NOT NULL,
  observed_at timestamptz NOT NULL,
  succeeded boolean NOT NULL,
  latency_ms integer NOT NULL CHECK (latency_ms >= 0),
  error_class text,
  PRIMARY KEY (tenant_id, provider_account_id, observed_at)
);
CREATE INDEX provider_outcome_window ON provider_outcome(tenant_id, provider_account_id, observed_at DESC);

CREATE TABLE admin_action (
  action_id char(64) PRIMARY KEY,
  tenant_id uuid NOT NULL,
  action_type text NOT NULL CHECK (action_type IN ('WEBHOOK_REPLAY','PROVIDER_OVERRIDE','RECONCILIATION_RETRY','STATE_REPAIR')),
  target text NOT NULL,
  payload jsonb NOT NULL,
  payload_digest char(64) NOT NULL,
  proposer text NOT NULL,
  approver text,
  state text NOT NULL CHECK (state IN ('PROPOSED','APPROVED','EXECUTING','EXECUTED','REJECTED','UNKNOWN')),
  proposed_at timestamptz NOT NULL,
  approved_at timestamptz,
  execution_receipt text,
  CHECK (approver IS NULL OR approver <> proposer)
);

CREATE TABLE incident (
  incident_id text PRIMARY KEY,
  severity text NOT NULL CHECK (severity IN ('SEV0','SEV1','SEV2','SEV3')),
  service text NOT NULL,
  public_summary text NOT NULL,
  state text NOT NULL CHECK (state IN ('OPEN','MITIGATING','MONITORING','RESOLVED')),
  owner text NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  opened_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE deletion_job (
  job_id char(64) PRIMARY KEY,
  tenant_id uuid NOT NULL,
  data_class text NOT NULL,
  selection_digest char(64) NOT NULL,
  record_count bigint NOT NULL CHECK (record_count > 0),
  proposer text NOT NULL,
  approver text,
  executor text,
  state text NOT NULL CHECK (state IN ('PROPOSED','APPROVED','EXECUTING','BACKUP_EXPIRY_PENDING','COMPLETED','UNKNOWN')),
  legal_hold_clear boolean NOT NULL,
  execution_receipt text,
  backup_receipt text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (approver IS NULL OR approver <> proposer)
);

ALTER TABLE edge_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE edge_quota ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_fence ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_outcome ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action ENABLE ROW LEVEL SECURITY;
ALTER TABLE deletion_job ENABLE ROW LEVEL SECURITY;
CREATE POLICY edge_nonce_tenant ON edge_nonce USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY edge_quota_tenant ON edge_quota USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY resource_fence_tenant ON resource_fence USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY provider_health_tenant ON provider_health USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY provider_outcome_tenant ON provider_outcome USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY admin_action_tenant ON admin_action USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
CREATE POLICY deletion_job_tenant ON deletion_job USING (tenant_id = current_setting('elmpay.tenant_id')::uuid) WITH CHECK (tenant_id = current_setting('elmpay.tenant_id')::uuid);
