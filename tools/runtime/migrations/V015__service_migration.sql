PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS service_migration_project (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN (
    'LEGACY_ONLY',
    'DUAL_WRITE_LEGACY_AUTHORITATIVE',
    'DUAL_WRITE_PLATFORM_AUTHORITATIVE',
    'PLATFORM_ONLY',
    'ROLLED_BACK'
  )),
  phase_version INTEGER NOT NULL CHECK (phase_version > 0),
  configuration_digest TEXT NOT NULL CHECK (length(configuration_digest) = 64),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id)
);
CREATE TABLE IF NOT EXISTS service_migration_write_journal (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  provider_reference TEXT NOT NULL,
  provider_result_digest TEXT NOT NULL CHECK (length(provider_result_digest) = 64),
  authority TEXT NOT NULL CHECK (authority IN ('legacy', 'platform')),
  divergence_state TEXT NOT NULL CHECK (divergence_state IN ('PENDING', 'MATCHED', 'DIVERGED')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, operation_id),
  UNIQUE (tenant_id, project_id, idempotency_key),
  FOREIGN KEY (tenant_id, project_id)
    REFERENCES service_migration_project(tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS service_migration_projection_delivery (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  target TEXT NOT NULL CHECK (target IN ('legacy', 'platform')),
  payload_json TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
  state TEXT NOT NULL CHECK (state IN ('PENDING', 'IN_FLIGHT', 'ACKED')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_owner TEXT,
  lease_token INTEGER NOT NULL DEFAULT 0 CHECK (lease_token >= 0),
  lease_expires_at TEXT,
  acknowledged_at TEXT,
  last_error TEXT,
  PRIMARY KEY (tenant_id, project_id, operation_id, target),
  FOREIGN KEY (tenant_id, project_id, operation_id)
    REFERENCES service_migration_write_journal(tenant_id, project_id, operation_id)
);

CREATE INDEX IF NOT EXISTS service_migration_delivery_claim_idx
  ON service_migration_projection_delivery
     (tenant_id, project_id, target, state, next_attempt_at, lease_expires_at);

CREATE TABLE IF NOT EXISTS service_migration_backfill_record (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  source_record_id TEXT NOT NULL,
  source_position INTEGER NOT NULL CHECK (source_position >= 0),
  canonical_json TEXT NOT NULL,
  canonical_digest TEXT NOT NULL CHECK (length(canonical_digest) = 64),
  amount_minor INTEGER NOT NULL,
  imported_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, source_record_id),
  UNIQUE (tenant_id, project_id, source_position),
  FOREIGN KEY (tenant_id, project_id)
    REFERENCES service_migration_project(tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS service_migration_backfill_checkpoint (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  source_stream TEXT NOT NULL,
  last_position INTEGER NOT NULL CHECK (last_position >= -1),
  record_count INTEGER NOT NULL CHECK (record_count >= 0),
  amount_minor_sum INTEGER NOT NULL,
  last_page_digest TEXT NOT NULL CHECK (length(last_page_digest) = 64),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, source_stream),
  FOREIGN KEY (tenant_id, project_id)
    REFERENCES service_migration_project(tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS service_migration_cutover (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  cutover_id TEXT NOT NULL,
  expected_phase TEXT NOT NULL,
  target_phase TEXT NOT NULL,
  expected_phase_version INTEGER NOT NULL CHECK (expected_phase_version > 0),
  evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
  proposer TEXT NOT NULL,
  approver TEXT,
  state TEXT NOT NULL CHECK (state IN ('PROPOSED', 'APPLIED', 'REJECTED')),
  proposed_at TEXT NOT NULL,
  decided_at TEXT,
  PRIMARY KEY (tenant_id, project_id, cutover_id),
  FOREIGN KEY (tenant_id, project_id)
    REFERENCES service_migration_project(tenant_id, project_id),
  CHECK (approver IS NULL OR approver <> proposer)
);

CREATE TABLE IF NOT EXISTS service_migration_audit (
  sequence_no INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  action TEXT NOT NULL,
  object_digest TEXT NOT NULL CHECK (length(object_digest) = 64),
  occurred_at TEXT NOT NULL
);
