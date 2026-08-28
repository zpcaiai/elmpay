-- recon_run and recon_exception deliberately match contracts/sql/schema.sql.
-- The other tables are additive persistence for immutable source files,
-- deterministic matches, workflow history and signed exports.
CREATE TABLE IF NOT EXISTS statement_file (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('PROVIDER','BANK')),
  source text NOT NULL,
  sha256 text NOT NULL,
  parser_version text NOT NULL,
  raw_bytes bytea NOT NULL,
  ingested_at timestamptz NOT NULL,
  UNIQUE (tenant_id, kind, source, sha256, parser_version),
  UNIQUE (id, tenant_id)
);

CREATE TABLE IF NOT EXISTS statement_row (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  file_id uuid NOT NULL,
  row_number integer NOT NULL CHECK (row_number > 1),
  external_reference text NOT NULL,
  amount_minor bigint NOT NULL,
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  FOREIGN KEY (file_id, tenant_id) REFERENCES statement_file(id, tenant_id),
  UNIQUE (file_id, row_number)
);

CREATE TABLE IF NOT EXISTS recon_run (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  business_date text NOT NULL,
  provider text NOT NULL CHECK (provider IN ('wechat','alipay','stripe','paypal','apple_pay')),
  source_file_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('ingesting','matching','completed','failed')),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  cutoff_at timestamptz NOT NULL,
  input_manifest_sha256 text NOT NULL
);
ALTER TABLE recon_run ADD COLUMN IF NOT EXISTS cutoff_at timestamptz;
ALTER TABLE recon_run ADD COLUMN IF NOT EXISTS input_manifest_sha256 text;
-- Preserve contract-first historical runs while making every runtime read
-- total and deterministic. Legacy values are marked by their original source
-- digest; they are not treated as a newly verified input manifest.
UPDATE recon_run
   SET cutoff_at = COALESCE(cutoff_at, completed_at, started_at),
       input_manifest_sha256 = COALESCE(input_manifest_sha256,
                                        'legacy:' || source_file_digest)
 WHERE cutoff_at IS NULL OR input_manifest_sha256 IS NULL;
ALTER TABLE recon_run ALTER COLUMN cutoff_at SET NOT NULL;
ALTER TABLE recon_run ALTER COLUMN input_manifest_sha256 SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS recon_run_tenant_identity_unique
  ON recon_run (id, tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS recon_run_source_unique
  ON recon_run (tenant_id, provider, business_date, source_file_digest);

CREATE TABLE IF NOT EXISTS recon_match (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  match_key text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('MATCHED','MISSING_SOURCE','AMOUNT_MISMATCH','DUPLICATE_SOURCE')),
  source_totals_json text NOT NULL,
  created_at timestamptz NOT NULL,
  FOREIGN KEY (run_id, tenant_id) REFERENCES recon_run(id, tenant_id),
  UNIQUE (run_id, match_key)
);

CREATE TABLE IF NOT EXISTS recon_exception (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL REFERENCES recon_run(id),
  category text NOT NULL CHECK (category IN ('missing_in_platform','missing_in_provider','amount_mismatch','status_mismatch','duplicate','fee_mismatch','timing')),
  payment_intent_id uuid,
  amount_minor bigint CHECK (amount_minor IS NULL OR amount_minor > 0),
  currency char(3) CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
  state text NOT NULL CHECK (state IN ('open','investigating','resolved','written_off')),
  resolution_reason text,
  approved_by text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
ALTER TABLE recon_exception
  DROP CONSTRAINT IF EXISTS recon_exception_run_id_fk;
ALTER TABLE recon_exception
  DROP CONSTRAINT IF EXISTS recon_exception_run_tenant_fk;
ALTER TABLE recon_exception
  ADD CONSTRAINT recon_exception_run_tenant_fk
  FOREIGN KEY (run_id, tenant_id) REFERENCES recon_run(id, tenant_id);
ALTER TABLE recon_exception
  DROP CONSTRAINT IF EXISTS recon_exception_writeoff_approval_check;
ALTER TABLE recon_exception
  ADD CONSTRAINT recon_exception_writeoff_approval_check
  CHECK (state <> 'written_off'
         OR (resolution_reason IS NOT NULL AND length(trim(resolution_reason)) > 0
             AND approved_by IS NOT NULL AND length(trim(approved_by)) > 0))
  NOT VALID;

CREATE TABLE IF NOT EXISTS recon_exception_action (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  exception_id uuid NOT NULL,
  action text NOT NULL,
  actor_id text NOT NULL,
  reason text NOT NULL,
  ledger_transaction_id uuid,
  created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS recon_exception_current (
  id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  match_key text NOT NULL,
  status text NOT NULL,
  owner_id text,
  proposer_id text,
  approver_id text,
  adjustment_minor bigint NOT NULL,
  currency char(3),
  version bigint NOT NULL CHECK (version > 0),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (id, tenant_id),
  CHECK (proposer_id IS NULL OR approver_id IS NULL OR proposer_id <> approver_id)
);
ALTER TABLE recon_exception_action
  DROP CONSTRAINT IF EXISTS recon_exception_action_current_tenant_fk;
ALTER TABLE recon_exception_action
  ADD CONSTRAINT recon_exception_action_current_tenant_fk
  FOREIGN KEY (exception_id, tenant_id)
  REFERENCES recon_exception_current(id, tenant_id);

CREATE TABLE IF NOT EXISTS financial_export (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  source_digest text NOT NULL,
  manifest_signature text NOT NULL,
  object_digest text NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, period_start, period_end, source_digest)
);

CREATE OR REPLACE FUNCTION elmpay_immutable_recon_source() RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  RAISE EXCEPTION 'statement and reconciliation history is immutable' USING ERRCODE = '55000';
END;
$elmpay$;

DROP TRIGGER IF EXISTS statement_file_immutable ON statement_file;
CREATE TRIGGER statement_file_immutable BEFORE UPDATE OR DELETE ON statement_file
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_recon_source();
DROP TRIGGER IF EXISTS statement_row_immutable ON statement_row;
CREATE TRIGGER statement_row_immutable BEFORE UPDATE OR DELETE ON statement_row
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_recon_source();
DROP TRIGGER IF EXISTS financial_export_immutable ON financial_export;
CREATE TRIGGER financial_export_immutable BEFORE UPDATE OR DELETE ON financial_export
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_recon_source();
DROP TRIGGER IF EXISTS recon_match_immutable ON recon_match;
CREATE TRIGGER recon_match_immutable BEFORE UPDATE OR DELETE ON recon_match
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_recon_source();
DROP TRIGGER IF EXISTS recon_exception_action_immutable ON recon_exception_action;
CREATE TRIGGER recon_exception_action_immutable BEFORE UPDATE OR DELETE ON recon_exception_action
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_recon_source();

CREATE OR REPLACE FUNCTION elmpay_protect_recon_run_snapshot() RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.business_date <> OLD.business_date OR NEW.provider <> OLD.provider
     OR NEW.source_file_digest <> OLD.source_file_digest
     OR NEW.started_at <> OLD.started_at OR NEW.cutoff_at <> OLD.cutoff_at
     OR NEW.input_manifest_sha256 <> OLD.input_manifest_sha256 THEN
    RAISE EXCEPTION 'reconciliation run input snapshot is immutable' USING ERRCODE = '55000';
  END IF;
  IF NOT (
    NEW.state = OLD.state
    OR (OLD.state = 'ingesting' AND NEW.state IN ('matching','failed'))
    OR (OLD.state = 'matching' AND NEW.state IN ('completed','failed'))
  ) THEN
    RAISE EXCEPTION 'invalid reconciliation run transition' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS recon_run_snapshot_guard ON recon_run;
CREATE TRIGGER recon_run_snapshot_guard BEFORE UPDATE ON recon_run
FOR EACH ROW EXECUTE FUNCTION elmpay_protect_recon_run_snapshot();
DROP TRIGGER IF EXISTS recon_run_no_delete ON recon_run;
CREATE TRIGGER recon_run_no_delete BEFORE DELETE ON recon_run
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_recon_source();

ALTER TABLE statement_file ENABLE ROW LEVEL SECURITY;
ALTER TABLE statement_file FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS statement_file_tenant_isolation ON statement_file;
CREATE POLICY statement_file_tenant_isolation ON statement_file
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE statement_row ENABLE ROW LEVEL SECURITY;
ALTER TABLE statement_row FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS statement_row_tenant_isolation ON statement_row;
CREATE POLICY statement_row_tenant_isolation ON statement_row
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE recon_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_run FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_run_tenant_isolation ON recon_run;
CREATE POLICY recon_run_tenant_isolation ON recon_run
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE recon_match ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_match FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_match_tenant_isolation ON recon_match;
CREATE POLICY recon_match_tenant_isolation ON recon_match
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE recon_exception ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_tenant_isolation ON recon_exception;
CREATE POLICY recon_exception_tenant_isolation ON recon_exception
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE recon_exception_action ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception_action FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_action_tenant_isolation ON recon_exception_action;
CREATE POLICY recon_exception_action_tenant_isolation ON recon_exception_action
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE recon_exception_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception_current FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_current_tenant_isolation ON recon_exception_current;
CREATE POLICY recon_exception_current_tenant_isolation ON recon_exception_current
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE financial_export ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_export FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_export_tenant_isolation ON financial_export;
CREATE POLICY financial_export_tenant_isolation ON financial_export
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON statement_file, statement_row, recon_match, recon_exception_action, financial_export FROM PUBLIC;
