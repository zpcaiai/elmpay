-- B78/B79 additive runtime controls. Published reconciliation migrations remain untouched.
ALTER TABLE financial_export ADD COLUMN IF NOT EXISTS signing_key_version text
  NOT NULL DEFAULT 'legacy-unversioned';
ALTER TABLE financial_export ALTER COLUMN signing_key_version DROP DEFAULT;

CREATE TABLE IF NOT EXISTS financial_runtime_job (
    tenant_id uuid NOT NULL,
    job_name text NOT NULL,
    business_date date NOT NULL,
    state text NOT NULL CHECK (state IN ('queued','running','completed','failed')),
    lease_owner text,
    lease_until timestamptz,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    input_manifest_sha256 char(64),
    result_reference text,
    last_error_code text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, job_name, business_date),
    CHECK ((state = 'running' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR state <> 'running')
);

CREATE TABLE IF NOT EXISTS financial_admin_audit (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    before_digest char(64) NOT NULL,
    after_digest char(64) NOT NULL,
    occurred_at timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS recon_match_id_tenant_unique
  ON recon_match(id, tenant_id);
CREATE TABLE IF NOT EXISTS recon_exception_origin (
    exception_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    match_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (exception_id, tenant_id),
    FOREIGN KEY (exception_id, tenant_id)
      REFERENCES recon_exception_current(id, tenant_id),
    FOREIGN KEY (run_id, tenant_id) REFERENCES recon_run(id, tenant_id),
    FOREIGN KEY (match_id, tenant_id) REFERENCES recon_match(id, tenant_id)
);

CREATE OR REPLACE FUNCTION elmpay_immutable_financial_admin_history()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  RAISE EXCEPTION 'financial admin audit is immutable' USING ERRCODE = '55000';
END;
$elmpay$;
DROP TRIGGER IF EXISTS financial_admin_audit_immutable ON financial_admin_audit;
CREATE TRIGGER financial_admin_audit_immutable BEFORE UPDATE OR DELETE ON financial_admin_audit
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_financial_admin_history();
DROP TRIGGER IF EXISTS recon_exception_origin_immutable ON recon_exception_origin;
CREATE TRIGGER recon_exception_origin_immutable BEFORE UPDATE OR DELETE ON recon_exception_origin
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_financial_admin_history();

ALTER TABLE financial_runtime_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_runtime_job FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_runtime_job_tenant_policy ON financial_runtime_job;
CREATE POLICY financial_runtime_job_tenant_policy ON financial_runtime_job
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE financial_admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_admin_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_admin_audit_tenant_policy ON financial_admin_audit;
CREATE POLICY financial_admin_audit_tenant_policy ON financial_admin_audit
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE recon_exception_origin ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception_origin FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_origin_tenant_policy ON recon_exception_origin;
CREATE POLICY recon_exception_origin_tenant_policy ON recon_exception_origin
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON financial_admin_audit, recon_exception_origin FROM PUBLIC;
