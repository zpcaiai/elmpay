-- Durable hosted-checkout sessions. The browser bearer/signing key are never stored.
CREATE TABLE IF NOT EXISTS checkout_session (
    session_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL REFERENCES payment_intent(id),
    business_order_no text NOT NULL CHECK (length(business_order_no) BETWEEN 1 AND 128),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    return_route_id text NOT NULL CHECK (return_route_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    return_uri text NOT NULL CHECK (return_uri ~ '^https://'),
    device_context_digest text NOT NULL,
    expires_at timestamptz NOT NULL,
    key_id text NOT NULL,
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
    allowed_methods text[] NOT NULL CHECK (cardinality(allowed_methods) > 0),
    create_idempotency_key text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    CHECK (expires_at > created_at),
    UNIQUE (tenant_id, project_id, create_idempotency_key),
    UNIQUE (tenant_id, payment_intent_id)
);

CREATE INDEX IF NOT EXISTS checkout_session_expiry
    ON checkout_session (tenant_id, expires_at);

ALTER TABLE checkout_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkout_session FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS checkout_session_tenant_isolation ON checkout_session;
CREATE POLICY checkout_session_tenant_isolation ON checkout_session
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

DROP TRIGGER IF EXISTS checkout_session_immutable ON checkout_session;
CREATE TRIGGER checkout_session_immutable
BEFORE UPDATE ON checkout_session FOR EACH ROW EXECUTE FUNCTION elmpay_reject_mutation();
