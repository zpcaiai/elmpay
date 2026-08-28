-- B62 device-aware capability and provider-health read model.
ALTER TABLE provider_capability
  ADD COLUMN IF NOT EXISTS device_classes text[] NOT NULL
    DEFAULT ARRAY['WEB','IOS','ANDROID','FLUTTER']::text[];

DO $elmpay$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'provider_capability_device_classes_check'
       AND conrelid = 'provider_capability'::regclass
  ) THEN
    ALTER TABLE provider_capability
      ADD CONSTRAINT provider_capability_device_classes_check
      CHECK (cardinality(device_classes) > 0
        AND device_classes <@ ARRAY['WEB','IOS','ANDROID','FLUTTER']::text[]);
  END IF;
END;
$elmpay$;

CREATE UNIQUE INDEX IF NOT EXISTS provider_account_tenant_identity
  ON provider_account(id, tenant_id, project_id);

CREATE TABLE IF NOT EXISTS provider_method_health (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    method text NOT NULL CHECK (method ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    available boolean NOT NULL,
    observed_at timestamptz NOT NULL,
    source_version text NOT NULL CHECK (length(source_version) BETWEEN 1 AND 128),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, provider_account_id, method),
    FOREIGN KEY (provider_account_id, tenant_id, project_id)
      REFERENCES provider_account(id, tenant_id, project_id),
    CHECK (updated_at >= observed_at)
);

CREATE INDEX IF NOT EXISTS provider_method_health_observed_idx
  ON provider_method_health(tenant_id, project_id, observed_at);

CREATE OR REPLACE FUNCTION elmpay_provider_health_transition()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id
     OR NEW.provider_account_id <> OLD.provider_account_id
     OR NEW.method <> OLD.method OR NEW.observed_at < OLD.observed_at
     OR NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'invalid provider health transition' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS provider_method_health_transition_guard ON provider_method_health;
CREATE TRIGGER provider_method_health_transition_guard
BEFORE UPDATE ON provider_method_health FOR EACH ROW
EXECUTE FUNCTION elmpay_provider_health_transition();
DROP TRIGGER IF EXISTS provider_method_health_no_delete ON provider_method_health;
CREATE TRIGGER provider_method_health_no_delete
BEFORE DELETE ON provider_method_health FOR EACH ROW EXECUTE FUNCTION elmpay_reject_mutation();

ALTER TABLE provider_method_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_method_health FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_method_health_tenant_policy ON provider_method_health;
CREATE POLICY provider_method_health_tenant_policy ON provider_method_health
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
