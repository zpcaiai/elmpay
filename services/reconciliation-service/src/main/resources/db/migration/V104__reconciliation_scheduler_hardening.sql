-- Additive hardening for the B76/B77 reconciliation scheduler.
-- V079_1 is checksum-bound and intentionally remains immutable. This migration replaces only
-- trigger bodies so an already-installed database can upgrade without rebasing history.

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

CREATE OR REPLACE FUNCTION elmpay_guard_financial_runtime_job()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'financial jobs cannot be deleted' USING ERRCODE = '55000';
  END IF;
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
CREATE TRIGGER financial_runtime_job_guard BEFORE UPDATE OR DELETE ON financial_runtime_job
FOR EACH ROW EXECUTE FUNCTION elmpay_guard_financial_runtime_job();

REVOKE EXECUTE ON FUNCTION elmpay_initialize_reconciliation_schedule_cursor(),
    elmpay_guard_reconciliation_schedule_cursor(),
    elmpay_initialize_financial_runtime_job(),
    elmpay_guard_financial_runtime_job() FROM PUBLIC;
