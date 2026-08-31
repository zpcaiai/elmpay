-- Forward-only B24 hardening. Historical evidence_flags remain untouched but are never
-- accepted for a transition after this migration.
ALTER TABLE tenant_registry
  ADD COLUMN IF NOT EXISTS last_transition_receipt_digests text[]
    NOT NULL DEFAULT ARRAY[]::text[],
  ADD COLUMN IF NOT EXISTS last_transition_audit_id uuid;

CREATE TABLE IF NOT EXISTS tenant_authority_evidence_nonce (
    tenant_id uuid NOT NULL REFERENCES tenant_registry(id),
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9._:-]{16,160}$'),
    evidence_type text NOT NULL CHECK (evidence_type IN
        ('KYB_VERIFIED', 'CONTRACT_SIGNED', 'SETTLEMENT_COMPLETE',
         'RETENTION_PERIOD_STARTED', 'KEK_DESTROYED')),
    authority text NOT NULL CHECK (authority ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$'),
    decision_reference text NOT NULL
      CHECK (decision_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{3,255}$'),
    payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    accepted_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (key_id, nonce)
);

CREATE UNIQUE INDEX IF NOT EXISTS merchant_control_audit_tenant_id_idx
  ON merchant_control_audit(tenant_id, id);

CREATE TABLE IF NOT EXISTS merchant_tenant_authority_evidence_audit (
    sequence_no bigserial PRIMARY KEY,
    id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    control_audit_id uuid NOT NULL,
    evidence_type text NOT NULL CHECK (evidence_type IN
        ('KYB_VERIFIED', 'CONTRACT_SIGNED', 'SETTLEMENT_COMPLETE',
         'RETENTION_PERIOD_STARTED', 'KEK_DESTROYED')),
    authority text NOT NULL,
    decision_reference text NOT NULL,
    payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    receipt_digest char(64) NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    signer_identity text NOT NULL,
    key_id text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    FOREIGN KEY (tenant_id, control_audit_id)
      REFERENCES merchant_control_audit(tenant_id, id),
    UNIQUE (control_audit_id, evidence_type),
    UNIQUE (control_audit_id, receipt_digest)
);

CREATE OR REPLACE FUNCTION elmpay_stamp_tenant_evidence_acceptance()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  NEW.accepted_at := statement_timestamp();
  RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS tenant_authority_evidence_acceptance_time
  ON tenant_authority_evidence_nonce;
CREATE TRIGGER tenant_authority_evidence_acceptance_time
BEFORE INSERT ON tenant_authority_evidence_nonce
FOR EACH ROW EXECUTE FUNCTION elmpay_stamp_tenant_evidence_acceptance();

CREATE OR REPLACE FUNCTION elmpay_transition_has_verified_tenant_evidence(
    requested_audit_id uuid, requested_tenant_id uuid, requested_type text,
    requested_digests text[])
RETURNS boolean LANGUAGE sql STABLE AS $elmpay$
  SELECT EXISTS (
    SELECT 1
      FROM merchant_tenant_authority_evidence_audit evidence
      JOIN tenant_authority_evidence_nonce accepted
        ON accepted.tenant_id = evidence.tenant_id
       AND accepted.key_id = evidence.key_id
       AND accepted.evidence_type = evidence.evidence_type
       AND accepted.authority = evidence.authority
       AND accepted.decision_reference = evidence.decision_reference
       AND accepted.payload_digest = evidence.payload_digest
       AND accepted.receipt_digest = evidence.receipt_digest
       AND accepted.issued_at = evidence.issued_at
       AND accepted.expires_at = evidence.expires_at
     WHERE evidence.control_audit_id = requested_audit_id
       AND evidence.tenant_id = requested_tenant_id
       AND evidence.evidence_type = requested_type
       AND evidence.receipt_digest = ANY(requested_digests)
       AND accepted.accepted_at >= statement_timestamp() - interval '10 minutes'
       AND accepted.accepted_at <= statement_timestamp()
       AND accepted.expires_at > statement_timestamp()
  );
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_validate_tenant_registry_transition()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
DECLARE
  receipt_count integer;
BEGIN
  IF NEW.version <> OLD.version + 1 OR NEW.id <> OLD.id
     OR NEW.external_reference <> OLD.external_reference OR NEW.code <> OLD.code THEN
    RAISE EXCEPTION 'tenant identity is immutable and version must advance exactly once';
  END IF;
  IF NOT ((OLD.state = 'DRAFT' AND NEW.state = 'ACTIVE')
      OR (OLD.state = 'ACTIVE' AND NEW.state IN ('SUSPENDED', 'OFFBOARDING'))
      OR (OLD.state = 'SUSPENDED' AND NEW.state IN ('ACTIVE', 'OFFBOARDING'))
      OR (OLD.state = 'OFFBOARDING' AND NEW.state = 'CLOSED')) THEN
    RAISE EXCEPTION 'illegal tenant lifecycle transition: % -> %', OLD.state, NEW.state;
  END IF;
  IF NEW.last_transition_audit_id IS NULL
     OR NEW.last_transition_audit_id IS NOT DISTINCT FROM OLD.last_transition_audit_id
     OR cardinality(NEW.last_transition_evidence_flags) <> 0
     OR EXISTS (SELECT 1
                  FROM unnest(NEW.last_transition_receipt_digests) AS item(digest)
                 WHERE item.digest !~ '^[0-9a-f]{64}$')
     OR NOT EXISTS (
       SELECT 1 FROM merchant_control_audit audit
        WHERE audit.id = NEW.last_transition_audit_id
          AND audit.tenant_id = NEW.id
          AND audit.action = 'TENANT_STATE_CHANGED'
          AND audit.target_type = 'tenant'
          AND audit.target_id = NEW.id::text
          AND audit.actor_id = NEW.last_transition_actor_id
          AND cardinality(audit.evidence_flags) = 0
          AND audit.second_approver_id IS NOT DISTINCT FROM
              NEW.last_transition_second_approver_id
          AND audit.occurred_at >= statement_timestamp() - interval '10 minutes'
          AND audit.occurred_at <= statement_timestamp() + interval '2 minutes') THEN
    RAISE EXCEPTION 'new tenant transitions require a fresh digest-bound audit';
  END IF;

  SELECT count(*) INTO receipt_count
    FROM merchant_tenant_authority_evidence_audit evidence
   WHERE evidence.tenant_id = NEW.id
     AND evidence.control_audit_id = NEW.last_transition_audit_id;

  IF OLD.state = 'DRAFT' AND NEW.state = 'ACTIVE' THEN
    IF cardinality(NEW.last_transition_receipt_digests) <> 2 OR receipt_count <> 2
       OR NOT elmpay_transition_has_verified_tenant_evidence(
           NEW.last_transition_audit_id, NEW.id, 'KYB_VERIFIED',
           NEW.last_transition_receipt_digests)
       OR NOT elmpay_transition_has_verified_tenant_evidence(
           NEW.last_transition_audit_id, NEW.id, 'CONTRACT_SIGNED',
           NEW.last_transition_receipt_digests) THEN
      RAISE EXCEPTION 'tenant activation requires verified KYB and contract receipts';
    END IF;
  ELSIF OLD.state = 'OFFBOARDING' AND NEW.state = 'CLOSED' THEN
    IF cardinality(NEW.last_transition_receipt_digests) <> 3 OR receipt_count <> 3
       OR NOT elmpay_transition_has_verified_tenant_evidence(
           NEW.last_transition_audit_id, NEW.id, 'SETTLEMENT_COMPLETE',
           NEW.last_transition_receipt_digests)
       OR NOT elmpay_transition_has_verified_tenant_evidence(
           NEW.last_transition_audit_id, NEW.id, 'RETENTION_PERIOD_STARTED',
           NEW.last_transition_receipt_digests)
       OR NOT elmpay_transition_has_verified_tenant_evidence(
           NEW.last_transition_audit_id, NEW.id, 'KEK_DESTROYED',
           NEW.last_transition_receipt_digests) THEN
      RAISE EXCEPTION 'tenant closure requires settlement, retention and KEK receipts';
    END IF;
  ELSIF cardinality(NEW.last_transition_receipt_digests) <> 0 OR receipt_count <> 0 THEN
    RAISE EXCEPTION 'tenant transition contains unexpected authority evidence';
  END IF;

  IF (NEW.state = 'OFFBOARDING'
      OR (OLD.state = 'SUSPENDED' AND NEW.state = 'ACTIVE'))
     AND (NEW.last_transition_second_approver_id IS NULL
          OR NEW.last_transition_second_approver_id = NEW.last_transition_actor_id) THEN
    RAISE EXCEPTION 'tenant transition requires a distinct second approver';
  END IF;
  RETURN NEW;
END;
$elmpay$;

ALTER TABLE tenant_authority_evidence_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_authority_evidence_nonce FORCE ROW LEVEL SECURITY;
ALTER TABLE merchant_tenant_authority_evidence_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_tenant_authority_evidence_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_authority_evidence_nonce_tenant_policy
  ON tenant_authority_evidence_nonce;
CREATE POLICY tenant_authority_evidence_nonce_tenant_policy
  ON tenant_authority_evidence_nonce
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS merchant_tenant_authority_evidence_audit_tenant_policy
  ON merchant_tenant_authority_evidence_audit;
CREATE POLICY merchant_tenant_authority_evidence_audit_tenant_policy
  ON merchant_tenant_authority_evidence_audit
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

DROP TRIGGER IF EXISTS tenant_authority_evidence_nonce_immutable
  ON tenant_authority_evidence_nonce;
CREATE TRIGGER tenant_authority_evidence_nonce_immutable
BEFORE UPDATE OR DELETE ON tenant_authority_evidence_nonce
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_merchant_control_audit_mutation();

DROP TRIGGER IF EXISTS merchant_tenant_authority_evidence_audit_immutable
  ON merchant_tenant_authority_evidence_audit;
CREATE TRIGGER merchant_tenant_authority_evidence_audit_immutable
BEFORE UPDATE OR DELETE ON merchant_tenant_authority_evidence_audit
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_merchant_control_audit_mutation();

REVOKE UPDATE, DELETE ON tenant_authority_evidence_nonce FROM PUBLIC;
REVOKE UPDATE, DELETE ON merchant_tenant_authority_evidence_audit FROM PUBLIC;
