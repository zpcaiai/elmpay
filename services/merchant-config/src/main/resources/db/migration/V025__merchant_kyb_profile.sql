-- B25 stores metadata and licensed-verifier decisions, never raw KYB document contents.
CREATE TABLE IF NOT EXISTS merchant_profile (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenant_registry(id),
    project_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    legal_name text NOT NULL,
    entity_kind text NOT NULL CHECK (entity_kind IN
        ('company', 'sole_trader', 'individual')),
    registration_country char(2) NOT NULL
        CHECK (registration_country ~ '^[A-Z]{2}$'),
    operating_region text NOT NULL CHECK (operating_region IN ('CN', 'HK', 'SG', 'EU')),
    settlement_currency char(3) NOT NULL,
    business_category text NOT NULL CHECK (business_category IN
        ('retail_goods', 'digital_services', 'travel')),
    risk_level text NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    document_references text[] NOT NULL CHECK (cardinality(document_references) > 0),
    profile_digest char(64) NOT NULL CHECK (profile_digest ~ '^[0-9a-f]{64}$'),
    verification_status text NOT NULL CHECK (verification_status IN
        ('PENDING', 'VERIFIED', 'REJECTED', 'EXPIRED')),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, project_id, merchant_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES project_registry(tenant_id, id)
    ,CHECK ((operating_region = 'CN' AND settlement_currency = 'CNY'
             AND registration_country = 'CN')
        OR (operating_region = 'HK' AND settlement_currency IN ('HKD', 'USD'))
        OR (operating_region = 'SG' AND settlement_currency IN ('SGD', 'USD'))
        OR (operating_region = 'EU' AND settlement_currency = 'EUR'))
    ,CHECK ((business_category = 'retail_goods' AND risk_level = 'LOW')
        OR (business_category = 'digital_services' AND risk_level = 'MEDIUM')
        OR (business_category = 'travel' AND risk_level = 'HIGH'))
);

CREATE TABLE IF NOT EXISTS merchant_verification_decision (
    sequence_no bigserial PRIMARY KEY,
    id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_digest char(64) NOT NULL CHECK (profile_digest ~ '^[0-9a-f]{64}$'),
    authority text NOT NULL,
    decision_reference text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('VERIFIED', 'REJECTED')),
    approver_ids text[] NOT NULL CHECK (cardinality(approver_ids) >= 1),
    decided_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > decided_at),
    recorded_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, profile_id) REFERENCES merchant_profile(tenant_id, id),
    UNIQUE (tenant_id, authority, decision_reference)
);

CREATE OR REPLACE FUNCTION elmpay_validate_verification_approvers()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE required_approvers integer;
BEGIN
  SELECT CASE WHEN risk_level = 'HIGH' THEN 2 ELSE 1 END
    INTO required_approvers
    FROM merchant_profile
   WHERE tenant_id = NEW.tenant_id AND id = NEW.profile_id;
  IF cardinality(ARRAY(SELECT DISTINCT unnest(NEW.approver_ids))) < required_approvers THEN
    RAISE EXCEPTION 'merchant risk requires % distinct approvers', required_approvers;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS merchant_verification_approver_guard
    ON merchant_verification_decision;
CREATE TRIGGER merchant_verification_approver_guard
BEFORE INSERT ON merchant_verification_decision
FOR EACH ROW EXECUTE FUNCTION elmpay_validate_verification_approvers();

CREATE INDEX IF NOT EXISTS merchant_verification_expiry_idx
    ON merchant_verification_decision (tenant_id, valid_until)
    WHERE outcome = 'VERIFIED';

CREATE OR REPLACE FUNCTION elmpay_reject_verification_decision_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'licensed-verifier decisions are immutable';
END $$;

DROP TRIGGER IF EXISTS merchant_verification_decision_immutable
    ON merchant_verification_decision;
CREATE TRIGGER merchant_verification_decision_immutable
BEFORE UPDATE OR DELETE ON merchant_verification_decision
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_verification_decision_mutation();

ALTER TABLE merchant_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_profile FORCE ROW LEVEL SECURITY;
ALTER TABLE merchant_verification_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_verification_decision FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS merchant_profile_tenant_policy ON merchant_profile;
CREATE POLICY merchant_profile_tenant_policy ON merchant_profile
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS merchant_verification_decision_tenant_policy
    ON merchant_verification_decision;
CREATE POLICY merchant_verification_decision_tenant_policy
    ON merchant_verification_decision
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON merchant_verification_decision FROM PUBLIC;

-- Rollback: drop merchant_verification_decision then merchant_profile.
