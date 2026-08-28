CREATE TABLE audit_anchor_request (
    anchor_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    through_sequence bigint NOT NULL CHECK (through_sequence > 0),
    chain_hash char(64) NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('PENDING','LEASED','ANCHORED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    worker_id text,
    lease_until timestamptz,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    next_attempt_at timestamptz NOT NULL,
    anchored_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (anchor_id, tenant_id),
    UNIQUE (tenant_id, through_sequence),
    UNIQUE (tenant_id, chain_hash),
    CHECK ((state = 'LEASED') = (worker_id IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 80)
);

CREATE INDEX audit_anchor_request_due_idx
    ON audit_anchor_request (tenant_id, next_attempt_at, through_sequence)
    WHERE state IN ('PENDING','LEASED');

CREATE TABLE audit_anchor_receipt (
    tenant_id uuid NOT NULL,
    anchor_id uuid NOT NULL,
    authority_id text NOT NULL,
    external_receipt_id text NOT NULL,
    through_sequence bigint NOT NULL CHECK (through_sequence > 0),
    chain_hash char(64) NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
    anchored_at timestamptz NOT NULL,
    signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 32 AND 512),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, anchor_id),
    UNIQUE (authority_id, external_receipt_id),
    FOREIGN KEY (anchor_id, tenant_id) REFERENCES audit_anchor_request(anchor_id, tenant_id),
    CHECK (anchored_at BETWEEN received_at - interval '5 minutes'
                          AND received_at + interval '5 minutes')
);

ALTER TABLE audit_anchor_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchor_request FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_anchor_request_tenant_policy ON audit_anchor_request
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE audit_anchor_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchor_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_anchor_receipt_tenant_policy ON audit_anchor_receipt
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE OR REPLACE FUNCTION elmpay_reject_audit_anchor_receipt_mutation()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    RAISE EXCEPTION 'verified audit timestamp receipts are immutable';
END
$elmpay$;

CREATE TRIGGER audit_anchor_receipt_no_update
BEFORE UPDATE OR DELETE ON audit_anchor_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_audit_anchor_receipt_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON audit_anchor_receipt FROM PUBLIC;

-- Rollback is destructive and therefore manual: drop receipt trigger/table before request table.
