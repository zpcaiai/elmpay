-- B76/B77 durable, cutoff-bound four-source reconciliation snapshots.
-- V012_1, V072, V076 and V079 must already be installed.

ALTER TABLE statement_file
    ADD COLUMN IF NOT EXISTS reconciliation_provider text;
ALTER TABLE statement_file
    ADD COLUMN IF NOT EXISTS content_sha256 char(64)
      GENERATED ALWAYS AS (encode(sha256(raw_bytes), 'hex')) STORED;

ALTER TABLE statement_file ALTER COLUMN content_sha256 SET NOT NULL;
ALTER TABLE statement_file DROP CONSTRAINT IF EXISTS statement_file_content_sha256_format;
ALTER TABLE statement_file ADD CONSTRAINT statement_file_content_sha256_format
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE statement_file DROP CONSTRAINT IF EXISTS statement_file_reconciliation_provider;
ALTER TABLE statement_file ADD CONSTRAINT statement_file_reconciliation_provider
    CHECK (reconciliation_provider IS NULL OR reconciliation_provider IN
       ('wechat','alipay','stripe','paypal','apple_pay'));
CREATE UNIQUE INDEX IF NOT EXISTS statement_file_exact_content_unique
    ON statement_file (tenant_id, kind, source, parser_version, content_sha256);
CREATE INDEX IF NOT EXISTS statement_file_reconciliation_cutoff_idx
    ON statement_file (tenant_id, reconciliation_provider, kind, ingested_at, id);
ALTER TABLE statement_row DROP CONSTRAINT IF EXISTS statement_row_reconciliation_value_check;
ALTER TABLE statement_row ADD CONSTRAINT statement_row_reconciliation_value_check CHECK (
    amount_minor > 0
    AND event_type IN ('CAPTURE','REFUND')
    AND length(external_reference) BETWEEN 1 AND 160
    AND external_reference !~ '[[:cntrl:]]'
) NOT VALID;

ALTER TABLE financial_runtime_job DROP CONSTRAINT IF EXISTS financial_runtime_job_state_check;
ALTER TABLE financial_runtime_job ADD CONSTRAINT financial_runtime_job_state_check
    CHECK (state IN ('queued','running','completed','failed','unknown'));
ALTER TABLE financial_runtime_job
    ADD COLUMN IF NOT EXISTS cutoff_at timestamptz,
    ADD COLUMN IF NOT EXISTS source_set_sha256 char(64);
ALTER TABLE financial_runtime_job DROP CONSTRAINT IF EXISTS financial_runtime_job_source_digest;
ALTER TABLE financial_runtime_job ADD CONSTRAINT financial_runtime_job_source_digest
    CHECK (source_set_sha256 IS NULL OR source_set_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE financial_runtime_job DROP CONSTRAINT IF EXISTS financial_runtime_job_input_digest;
ALTER TABLE financial_runtime_job ADD CONSTRAINT financial_runtime_job_input_digest
    CHECK (input_manifest_sha256 IS NULL
      OR input_manifest_sha256 ~ '^[0-9a-f]{64}$') NOT VALID;
ALTER TABLE financial_runtime_job
    DROP CONSTRAINT IF EXISTS financial_runtime_job_lifecycle_check;
ALTER TABLE financial_runtime_job ADD CONSTRAINT financial_runtime_job_lifecycle_check CHECK (
    (state = 'queued' AND lease_owner IS NULL AND lease_until IS NULL
      AND result_reference IS NULL AND last_error_code IS NULL)
 OR (state = 'running' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL
      AND lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$'
      AND lease_until > updated_at
      AND result_reference IS NULL AND last_error_code IS NULL)
 OR (state = 'completed' AND lease_owner IS NULL AND lease_until IS NULL
      AND result_reference IS NOT NULL AND result_reference ~
          '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND last_error_code IS NULL)
 OR (state IN ('failed','unknown') AND lease_owner IS NULL AND lease_until IS NULL
      AND result_reference IS NULL AND last_error_code IS NOT NULL)
) NOT VALID;

ALTER TABLE recon_run DROP CONSTRAINT IF EXISTS recon_run_runtime_digest_check;
ALTER TABLE recon_run ADD CONSTRAINT recon_run_runtime_digest_check CHECK (
    source_file_digest ~ '^[0-9a-f]{64}$'
    AND input_manifest_sha256 ~ '^[0-9a-f]{64}$'
) NOT VALID;

CREATE TABLE IF NOT EXISTS reconciliation_fact_snapshot (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN
       ('wechat','alipay','stripe','paypal','apple_pay')),
    business_date date NOT NULL,
    cutoff_at timestamptz NOT NULL,
    source_set_sha256 char(64) NOT NULL CHECK (source_set_sha256 ~ '^[0-9a-f]{64}$'),
    input_manifest_sha256 char(64) NOT NULL CHECK (input_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    canonical_manifest text NOT NULL,
    business_count integer NOT NULL CHECK (business_count > 0),
    platform_count integer NOT NULL CHECK (platform_count > 0),
    provider_count integer NOT NULL CHECK (provider_count > 0),
    bank_count integer NOT NULL CHECK (bank_count > 0),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (id, tenant_id),
    UNIQUE (tenant_id, provider, business_date, cutoff_at),
    UNIQUE (tenant_id, provider, business_date, source_set_sha256)
);

CREATE TABLE IF NOT EXISTS reconciliation_fact_snapshot_member (
    snapshot_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    source text NOT NULL CHECK (source IN ('BUSINESS','PLATFORM','PROVIDER','BANK')),
    external_reference_sha256 char(64) NOT NULL
        CHECK (external_reference_sha256 ~ '^[0-9a-f]{64}$'),
    event_type text NOT NULL CHECK (event_type IN ('CAPTURE','REFUND')),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    occurred_at timestamptz NOT NULL,
    source_record_sha256 char(64) NOT NULL CHECK (source_record_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (snapshot_id, tenant_id, ordinal),
    FOREIGN KEY (snapshot_id, tenant_id)
      REFERENCES reconciliation_fact_snapshot(id, tenant_id)
);

CREATE TABLE IF NOT EXISTS reconciliation_schedule_cursor (
    tenant_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN
       ('wechat','alipay','stripe','paypal','apple_pay')),
    next_business_date date NOT NULL,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    failure_count bigint NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    last_failure_code text CHECK (last_failure_code IS NULL
      OR last_failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    last_failure_digest char(64) CHECK (last_failure_digest IS NULL
      OR last_failure_digest ~ '^[0-9a-f]{64}$'),
    last_failure_at timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider),
    CHECK ((last_failure_code IS NULL AND last_failure_digest IS NULL
             AND last_failure_at IS NULL)
        OR (last_failure_code IS NOT NULL AND last_failure_digest IS NOT NULL
             AND last_failure_at IS NOT NULL))
);

CREATE OR REPLACE FUNCTION elmpay_initialize_reconciliation_schedule_cursor()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
DECLARE
  oldest_source_date date;
BEGIN
  IF NEW.fencing_token <> 0 OR NEW.failure_count <> 0
     OR NEW.last_failure_code IS NOT NULL OR NEW.last_failure_digest IS NOT NULL
     OR NEW.last_failure_at IS NOT NULL THEN
    RAISE EXCEPTION 'reconciliation schedule cursor must start at its canonical fence'
      USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (
    SELECT 1
      FROM public.provider_account account
     WHERE account.tenant_id = NEW.tenant_id AND account.provider = NEW.provider
       AND account.environment = 'production' AND account.status = 'active'
       AND EXISTS (
         SELECT 1 FROM public.provider_capability capability
          WHERE capability.tenant_id = account.tenant_id
            AND capability.provider_account_id = account.id)
  ) THEN
    RAISE EXCEPTION 'reconciliation schedule requires an active production provider account'
      USING ERRCODE = '23514';
  END IF;
  SELECT min(candidate.business_date)
    INTO oldest_source_date
    FROM (
      SELECT (event.occurred_at AT TIME ZONE 'UTC')::date AS business_date
        FROM public.outbox_event event
       WHERE event.tenant_id = NEW.tenant_id
         AND event.event_type IN ('payment_intent.captured','refund.succeeded')
         AND event.payload->>'provider' = NEW.provider
      UNION ALL
      SELECT (statement_entry.occurred_at AT TIME ZONE 'UTC')::date AS business_date
        FROM public.statement_file file
        JOIN public.statement_row statement_entry
          ON statement_entry.tenant_id = file.tenant_id
         AND statement_entry.file_id = file.id
       WHERE file.tenant_id = NEW.tenant_id
         AND file.reconciliation_provider = NEW.provider
    ) candidate;
  IF oldest_source_date IS NULL OR NEW.next_business_date <> oldest_source_date THEN
    RAISE EXCEPTION 'reconciliation schedule must start at the oldest immutable source date'
      USING ERRCODE = '23514';
  END IF;
  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$elmpay$;
DROP TRIGGER IF EXISTS reconciliation_schedule_cursor_initialize
    ON reconciliation_schedule_cursor;
CREATE TRIGGER reconciliation_schedule_cursor_initialize
BEFORE INSERT ON reconciliation_schedule_cursor
FOR EACH ROW EXECUTE FUNCTION elmpay_initialize_reconciliation_schedule_cursor();

CREATE OR REPLACE FUNCTION elmpay_guard_reconciliation_schedule_cursor()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
  NEW.updated_at := clock_timestamp();
  IF NEW.next_business_date = OLD.next_business_date
     AND NEW.failure_count = OLD.failure_count + 1 THEN
    NEW.last_failure_at := NEW.updated_at;
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.provider <> OLD.provider
     OR NEW.fencing_token <> OLD.fencing_token + 1
     OR NEW.updated_at < OLD.updated_at
     OR NOT (
       (NEW.next_business_date = OLD.next_business_date + 1
         AND NEW.failure_count = OLD.failure_count
         AND NEW.last_failure_code IS NULL
         AND NEW.last_failure_digest IS NULL
         AND NEW.last_failure_at IS NULL)
       OR
       (NEW.next_business_date = OLD.next_business_date
         AND NEW.failure_count = OLD.failure_count + 1
         AND NEW.last_failure_code IS NOT NULL
         AND NEW.last_failure_digest IS NOT NULL
         AND NEW.last_failure_at IS NOT DISTINCT FROM NEW.updated_at)
     ) THEN
    RAISE EXCEPTION 'invalid reconciliation schedule cursor advance' USING ERRCODE = '23514';
  END IF;
  IF NEW.next_business_date = OLD.next_business_date + 1 AND NOT EXISTS (
    SELECT 1
      FROM public.financial_runtime_job job
      JOIN public.recon_run run
        ON run.id::text = job.result_reference
       AND run.tenant_id = job.tenant_id
       AND run.provider = OLD.provider
       AND run.business_date = OLD.next_business_date::text
       AND run.state = 'completed'
       AND run.source_file_digest = job.source_set_sha256
       AND run.cutoff_at = job.cutoff_at
       AND run.input_manifest_sha256 = job.input_manifest_sha256
     WHERE job.tenant_id = OLD.tenant_id
       AND job.job_name = 'reconciliation:' || OLD.provider
       AND job.business_date = OLD.next_business_date
       AND job.state = 'completed'
  ) THEN
    RAISE EXCEPTION 'reconciliation cursor cannot advance without its exact completed run'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$elmpay$;
DROP TRIGGER IF EXISTS reconciliation_schedule_cursor_guard
    ON reconciliation_schedule_cursor;
CREATE TRIGGER reconciliation_schedule_cursor_guard
BEFORE UPDATE ON reconciliation_schedule_cursor
FOR EACH ROW EXECUTE FUNCTION elmpay_guard_reconciliation_schedule_cursor();

CREATE OR REPLACE FUNCTION elmpay_immutable_reconciliation_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  RAISE EXCEPTION 'reconciliation fact snapshots are immutable' USING ERRCODE = '55000';
END;
$elmpay$;
DROP TRIGGER IF EXISTS reconciliation_fact_snapshot_immutable
    ON reconciliation_fact_snapshot;
CREATE TRIGGER reconciliation_fact_snapshot_immutable
BEFORE UPDATE OR DELETE ON reconciliation_fact_snapshot
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_reconciliation_snapshot();
DROP TRIGGER IF EXISTS reconciliation_fact_snapshot_member_immutable
    ON reconciliation_fact_snapshot_member;
CREATE TRIGGER reconciliation_fact_snapshot_member_immutable
BEFORE UPDATE OR DELETE ON reconciliation_fact_snapshot_member
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_reconciliation_snapshot();

ALTER TABLE reconciliation_fact_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliation_fact_snapshot FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reconciliation_fact_snapshot_tenant_policy
    ON reconciliation_fact_snapshot;
CREATE POLICY reconciliation_fact_snapshot_tenant_policy ON reconciliation_fact_snapshot
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE reconciliation_fact_snapshot_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliation_fact_snapshot_member FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reconciliation_fact_snapshot_member_tenant_policy
    ON reconciliation_fact_snapshot_member;
CREATE POLICY reconciliation_fact_snapshot_member_tenant_policy
 ON reconciliation_fact_snapshot_member
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE reconciliation_schedule_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliation_schedule_cursor FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reconciliation_schedule_cursor_tenant_policy
    ON reconciliation_schedule_cursor;
CREATE POLICY reconciliation_schedule_cursor_tenant_policy
 ON reconciliation_schedule_cursor
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON reconciliation_fact_snapshot,
    reconciliation_fact_snapshot_member FROM PUBLIC;
REVOKE DELETE ON reconciliation_schedule_cursor FROM PUBLIC;

CREATE OR REPLACE FUNCTION elmpay_initialize_financial_runtime_job()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
  IF NEW.job_name NOT IN ('reconciliation:wechat','reconciliation:alipay',
                          'reconciliation:stripe','reconciliation:paypal',
                          'reconciliation:apple_pay')
     OR NEW.state <> 'queued' OR NEW.lease_owner IS NOT NULL
     OR NEW.lease_until IS NOT NULL OR NEW.fencing_token <> 0
     OR NEW.input_manifest_sha256 IS NULL OR NEW.cutoff_at IS NULL
     OR NEW.source_set_sha256 IS NULL OR NEW.result_reference IS NOT NULL
     OR NEW.last_error_code IS NOT NULL THEN
    RAISE EXCEPTION 'financial job must start as a canonical bound reconciliation job'
      USING ERRCODE = '23514';
  END IF;
  NEW.created_at := clock_timestamp();
  NEW.updated_at := NEW.created_at;
  RETURN NEW;
END;
$elmpay$;
DROP TRIGGER IF EXISTS financial_runtime_job_initialize ON financial_runtime_job;
CREATE TRIGGER financial_runtime_job_initialize BEFORE INSERT ON financial_runtime_job
FOR EACH ROW EXECUTE FUNCTION elmpay_initialize_financial_runtime_job();

CREATE OR REPLACE FUNCTION elmpay_guard_financial_runtime_job()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
  NEW.updated_at := clock_timestamp();
  IF OLD.state = 'completed' THEN
    RAISE EXCEPTION 'completed financial job is immutable' USING ERRCODE = '55000';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.job_name <> OLD.job_name
     OR NEW.business_date <> OLD.business_date
     OR NEW.input_manifest_sha256 IS DISTINCT FROM OLD.input_manifest_sha256
     OR NEW.cutoff_at IS DISTINCT FROM OLD.cutoff_at
     OR NEW.source_set_sha256 IS DISTINCT FROM OLD.source_set_sha256
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'financial job immutable identity changed' USING ERRCODE = '55000';
  END IF;
  IF NEW.updated_at < OLD.updated_at OR NEW.updated_at < NEW.created_at THEN
    RAISE EXCEPTION 'financial job timestamp moved backwards' USING ERRCODE = '23514';
  END IF;
  IF (NEW.state = 'running' AND
        (NEW.lease_owner IS NULL OR NEW.lease_until IS NULL
         OR NEW.lease_until <= NEW.updated_at
         OR NEW.lease_until > NEW.updated_at + interval '1 hour'
         OR NEW.lease_owner !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$'))
     OR (NEW.state <> 'running' AND
        (NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL)) THEN
    RAISE EXCEPTION 'financial job lease does not match state' USING ERRCODE = '23514';
  END IF;
  IF (NEW.state = 'completed' AND
        (NEW.result_reference IS NULL OR NEW.result_reference !~
          '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
     OR (NEW.state <> 'completed' AND NEW.result_reference IS NOT NULL) THEN
    RAISE EXCEPTION 'financial job result does not match state' USING ERRCODE = '23514';
  END IF;
  IF NEW.state = 'completed' AND NOT EXISTS (
    SELECT 1
      FROM public.recon_run run
     WHERE run.id::text = NEW.result_reference
       AND run.tenant_id = NEW.tenant_id
       AND run.provider = split_part(NEW.job_name, ':', 2)
       AND run.business_date = NEW.business_date::text
       AND run.state = 'completed'
       AND run.source_file_digest = NEW.source_set_sha256
       AND run.cutoff_at = NEW.cutoff_at
       AND run.input_manifest_sha256 = NEW.input_manifest_sha256
  ) THEN
    RAISE EXCEPTION 'financial job cannot complete without its exact completed run'
      USING ERRCODE = '23514';
  END IF;
  IF (NEW.state IN ('failed','unknown') AND NEW.last_error_code IS NULL)
     OR (NEW.state NOT IN ('failed','unknown') AND NEW.last_error_code IS NOT NULL) THEN
    RAISE EXCEPTION 'financial job error does not match state' USING ERRCODE = '23514';
  END IF;
  IF NOT ((OLD.state IN ('queued','failed','unknown') AND NEW.state = 'running')
      OR (OLD.state = 'running' AND NEW.state IN ('running','completed','failed','unknown'))) THEN
    RAISE EXCEPTION 'invalid financial job state transition' USING ERRCODE = '23514';
  END IF;
  IF OLD.state = 'running' AND NEW.state = 'running'
     AND OLD.lease_until > NEW.updated_at THEN
    RAISE EXCEPTION 'unexpired financial job lease cannot be replaced' USING ERRCODE = '23514';
  END IF;
  IF (NEW.state = 'running' AND NEW.fencing_token <> OLD.fencing_token + 1)
     OR (NEW.state <> 'running' AND NEW.fencing_token <> OLD.fencing_token) THEN
    RAISE EXCEPTION 'financial job fencing token did not advance' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$elmpay$;
DROP TRIGGER IF EXISTS financial_runtime_job_guard ON financial_runtime_job;
CREATE TRIGGER financial_runtime_job_guard BEFORE UPDATE ON financial_runtime_job
FOR EACH ROW EXECUTE FUNCTION elmpay_guard_financial_runtime_job();

REVOKE EXECUTE ON FUNCTION elmpay_initialize_reconciliation_schedule_cursor(),
    elmpay_guard_reconciliation_schedule_cursor(),
    elmpay_immutable_reconciliation_snapshot(),
    elmpay_initialize_financial_runtime_job(),
    elmpay_guard_financial_runtime_job() FROM PUBLIC;

-- The worker login is deliberately not BYPASSRLS. Expose only bounded active identifiers needed
-- to enter a tenant-scoped transaction; all payment and financial facts remain behind tenant RLS.
CREATE OR REPLACE FUNCTION elmpay_active_worker_scopes(
    p_after_tenant uuid,
    p_after_project uuid,
    p_maximum integer)
RETURNS TABLE (tenant_id uuid, project_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $elmpay$
BEGIN
  IF p_maximum < 1 OR p_maximum > 10000 THEN
    RAISE EXCEPTION 'maximum worker scopes must be 1..10000' USING ERRCODE = '22023';
  END IF;
  IF (p_after_tenant IS NULL) <> (p_after_project IS NULL) THEN
    RAISE EXCEPTION 'worker scope cursor must be entirely null or non-null'
      USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT tenant.id, project.id
    FROM public.tenant tenant
    JOIN public.project project ON project.tenant_id = tenant.id
   WHERE tenant.status = 'active' AND project.status = 'active'
     AND (p_after_tenant IS NULL
       OR (tenant.id, project.id) > (p_after_tenant, p_after_project))
   ORDER BY tenant.id, project.id
   LIMIT p_maximum;
END;
$elmpay$;

REVOKE ALL ON FUNCTION elmpay_active_worker_scopes(uuid, uuid, integer) FROM PUBLIC;
DO $elmpay$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'elmpay_worker') THEN
    GRANT EXECUTE ON FUNCTION elmpay_active_worker_scopes(uuid, uuid, integer)
      TO elmpay_worker;
  END IF;
END;
$elmpay$;
