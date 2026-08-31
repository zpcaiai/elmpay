-- Forward-only B66-B69 hardening: replace caller verification booleans with signed receipts.
-- Historical inbox rows intentionally remain NULL; the platform cannot invent old evidence.
ALTER TABLE dispute_event_inbox
  ADD COLUMN IF NOT EXISTS verification_receipt_digest char(64)
  CHECK (verification_receipt_digest IS NULL
    OR verification_receipt_digest ~ '^[0-9a-f]{64}$');

CREATE TABLE IF NOT EXISTS provider_evidence_nonce (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    key_id text NOT NULL,
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9._:-]{16,160}$'),
    evidence_type text NOT NULL CHECK (evidence_type ~ '^[A-Z][A-Z0-9_]{2,79}$'),
    entity_id text NOT NULL,
    receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY (key_id, nonce)
);

CREATE OR REPLACE FUNCTION elmpay_require_provider_evidence_receipt()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  IF NEW.verification_receipt_digest IS NULL THEN
    RAISE EXCEPTION 'new dispute events require verified provider evidence'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS dispute_event_requires_provider_evidence ON dispute_event_inbox;
CREATE TRIGGER dispute_event_requires_provider_evidence
BEFORE INSERT OR UPDATE OF verification_receipt_digest ON dispute_event_inbox
FOR EACH ROW EXECUTE FUNCTION elmpay_require_provider_evidence_receipt();

DROP TRIGGER IF EXISTS provider_evidence_nonce_immutable ON provider_evidence_nonce;
CREATE TRIGGER provider_evidence_nonce_immutable
BEFORE UPDATE OR DELETE ON provider_evidence_nonce
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();

ALTER TABLE provider_evidence_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_evidence_nonce FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_evidence_nonce_tenant_policy ON provider_evidence_nonce;
CREATE POLICY provider_evidence_nonce_tenant_policy ON provider_evidence_nonce
USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON provider_evidence_nonce FROM PUBLIC;
