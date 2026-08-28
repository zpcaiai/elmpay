-- Durable B57 payment links. Only SHA-256 token digests are stored.
CREATE UNIQUE INDEX IF NOT EXISTS checkout_session_tenant_identity
  ON checkout_session(session_id, tenant_id, project_id);

CREATE TABLE IF NOT EXISTS payment_link (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    checkout_session_id uuid NOT NULL,
    token_digest char(64) NOT NULL CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    signing_key_version text NOT NULL,
    idempotency_digest char(64) NOT NULL CHECK (idempotency_digest ~ '^[0-9a-f]{64}$'),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, project_id, idempotency_digest),
    UNIQUE (tenant_id, token_digest),
    UNIQUE (id, tenant_id, project_id),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    FOREIGN KEY (checkout_session_id, tenant_id, project_id)
      REFERENCES checkout_session(session_id, tenant_id, project_id)
);

CREATE INDEX IF NOT EXISTS payment_link_expiry_idx
  ON payment_link(tenant_id, expires_at) WHERE consumed_at IS NULL;

CREATE OR REPLACE FUNCTION elmpay_payment_link_transition()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.project_id <> OLD.project_id
     OR NEW.checkout_session_id <> OLD.checkout_session_id
     OR NEW.token_digest <> OLD.token_digest
     OR NEW.signing_key_version <> OLD.signing_key_version
     OR NEW.idempotency_digest <> OLD.idempotency_digest
     OR NEW.request_digest <> OLD.request_digest
     OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'payment link snapshot is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
     OR NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'invalid payment link transition' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS payment_link_transition_guard ON payment_link;
CREATE TRIGGER payment_link_transition_guard BEFORE UPDATE ON payment_link
FOR EACH ROW EXECUTE FUNCTION elmpay_payment_link_transition();
DROP TRIGGER IF EXISTS payment_link_no_delete ON payment_link;
CREATE TRIGGER payment_link_no_delete BEFORE DELETE ON payment_link
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_mutation();

ALTER TABLE payment_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_link FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS payment_link_tenant_policy ON payment_link;
CREATE POLICY payment_link_tenant_policy ON payment_link
 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
