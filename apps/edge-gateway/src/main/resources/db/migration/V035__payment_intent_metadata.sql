-- Immutable, non-sensitive metadata bound to one payment-intent create request.
CREATE TABLE IF NOT EXISTS payment_intent_metadata (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    create_idempotency_key text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, payment_intent_id),
    UNIQUE (tenant_id, create_idempotency_key),
    CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE OR REPLACE FUNCTION elmpay_validate_payment_intent_metadata()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    IF (SELECT count(*) FROM jsonb_each(NEW.metadata)) > 20 THEN
        RAISE EXCEPTION 'payment intent metadata has too many keys';
    END IF;
    RETURN NEW;
END;
$elmpay$;
DROP TRIGGER IF EXISTS payment_intent_metadata_guard ON payment_intent_metadata;
CREATE TRIGGER payment_intent_metadata_guard
BEFORE INSERT OR UPDATE ON payment_intent_metadata
FOR EACH ROW EXECUTE FUNCTION elmpay_validate_payment_intent_metadata();

ALTER TABLE payment_intent_metadata
    DROP CONSTRAINT IF EXISTS payment_intent_metadata_payment_intent_id_fkey;
ALTER TABLE payment_intent_metadata
    DROP CONSTRAINT IF EXISTS payment_intent_metadata_payment_tenant_fk;
ALTER TABLE payment_intent_metadata
    ADD CONSTRAINT payment_intent_metadata_payment_tenant_fk
    FOREIGN KEY (tenant_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, id);

ALTER TABLE payment_intent_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_intent_metadata FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS payment_intent_metadata_tenant_policy ON payment_intent_metadata;
CREATE POLICY payment_intent_metadata_tenant_policy ON payment_intent_metadata
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE INDEX IF NOT EXISTS payment_intent_metadata_lookup
    ON payment_intent_metadata(tenant_id, payment_intent_id);
