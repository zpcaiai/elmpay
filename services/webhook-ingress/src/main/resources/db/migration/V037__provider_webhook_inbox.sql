CREATE TABLE provider_webhook_inbox (
    inbox_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    merchant_account_id VARCHAR(64) NOT NULL,
    provider_event_id VARCHAR(160) NOT NULL,
    event_type VARCHAR(160) NOT NULL,
    provider_payment_id VARCHAR(160) NOT NULL,
    business_order_no VARCHAR(160) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    signature_key_id VARCHAR(160) NOT NULL,
    raw_body_sha256 CHAR(64) NOT NULL,
    raw_body BYTEA NOT NULL,
    canonical_payload BYTEA NOT NULL,
    processing_status VARCHAR(24) NOT NULL
        CHECK (processing_status IN ('VERIFIED', 'PROCESSING', 'PROCESSED', 'FAILED')),
    processing_attempts INTEGER NOT NULL DEFAULT 0 CHECK (processing_attempts >= 0),
    processed_at TIMESTAMPTZ,
    last_error_code VARCHAR(80),
    UNIQUE (tenant_id, provider, merchant_account_id, provider_event_id)
);

CREATE INDEX provider_webhook_inbox_pending_idx
    ON provider_webhook_inbox (received_at, inbox_id)
    WHERE processing_status IN ('VERIFIED', 'FAILED');

ALTER TABLE provider_webhook_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_webhook_inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_webhook_inbox_tenant_policy ON provider_webhook_inbox
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE webhook_ingress_endpoint (
    endpoint_id VARCHAR(64) PRIMARY KEY,
    token_digest CHAR(64) NOT NULL UNIQUE CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    tenant_id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    merchant_account_id VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE','PAUSED','REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    CHECK (provider ~ '^[a-z][a-z0-9-]{1,31}$')
);

ALTER TABLE webhook_ingress_endpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_ingress_endpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_ingress_endpoint_tenant_policy ON webhook_ingress_endpoint
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE FUNCTION elmpay_resolve_webhook_ingress_endpoint(request_token_digest text)
RETURNS TABLE (tenant_id VARCHAR(64), project_id VARCHAR(64), provider VARCHAR(32),
               merchant_account_id VARCHAR(64))
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = off
AS $elmpay$
    SELECT endpoint.tenant_id, endpoint.project_id, endpoint.provider,
           endpoint.merchant_account_id
      FROM public.webhook_ingress_endpoint endpoint
     WHERE endpoint.token_digest = request_token_digest
       AND endpoint.status = 'ACTIVE'
     LIMIT 2
$elmpay$;

REVOKE ALL ON webhook_ingress_endpoint FROM PUBLIC;
REVOKE ALL ON FUNCTION elmpay_resolve_webhook_ingress_endpoint(text) FROM PUBLIC;

-- Rollback: drop resolver, endpoint registry, then provider_webhook_inbox.
