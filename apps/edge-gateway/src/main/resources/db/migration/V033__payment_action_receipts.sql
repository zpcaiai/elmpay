CREATE TABLE IF NOT EXISTS payment_action_receipt (
    tenant_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL REFERENCES payment_intent(id),
    operation text NOT NULL CHECK (operation ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) >= 16),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    result_intent_version bigint NOT NULL CHECK (result_intent_version >= 1),
    completed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, payment_intent_id, idempotency_key)
);

ALTER TABLE payment_action_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_action_receipt FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS payment_action_receipt_tenant_policy ON payment_action_receipt;
CREATE POLICY payment_action_receipt_tenant_policy ON payment_action_receipt
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE OR REPLACE FUNCTION elmpay_reject_action_receipt_mutation()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    RAISE EXCEPTION 'completed payment action receipt is immutable';
END;
$elmpay$;

DROP TRIGGER IF EXISTS payment_action_receipt_immutable ON payment_action_receipt;
CREATE TRIGGER payment_action_receipt_immutable
BEFORE UPDATE OR DELETE ON payment_action_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_action_receipt_mutation();
