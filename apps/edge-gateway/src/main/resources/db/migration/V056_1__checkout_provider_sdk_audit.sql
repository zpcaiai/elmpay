-- B56 append-only authorization receipts for checkout provider SDK bootstrap.
CREATE TABLE IF NOT EXISTS checkout_provider_sdk_audit (
    audit_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    project_id uuid NOT NULL REFERENCES project(id),
    merchant_id uuid NOT NULL REFERENCES merchant(id),
    checkout_session_id uuid NOT NULL REFERENCES checkout_session(session_id),
    payment_intent_id uuid NOT NULL REFERENCES payment_intent(id),
    provider_account_id uuid NOT NULL REFERENCES provider_account(id),
    method text NOT NULL CHECK (method ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    provider text NOT NULL CHECK (provider ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    actor_type text NOT NULL CHECK (actor_type IN ('checkout_session', 'oauth_client')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 160),
    request_id text NOT NULL CHECK (length(request_id) BETWEEN 8 AND 128),
    channel_digest char(64) NOT NULL CHECK (channel_digest ~ '^[0-9a-f]{64}$'),
    business_order_digest char(64) NOT NULL CHECK (business_order_digest ~ '^[0-9a-f]{64}$'),
    checkout_snapshot_digest char(64) NOT NULL CHECK (checkout_snapshot_digest ~ '^[0-9a-f]{64}$'),
    configuration_digest char(64) NOT NULL CHECK (configuration_digest ~ '^[0-9a-f]{64}$'),
    capability_version text NOT NULL CHECK (length(capability_version) BETWEEN 1 AND 128),
    policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    session_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    CHECK (created_at < session_expires_at)
);

CREATE INDEX IF NOT EXISTS checkout_provider_sdk_audit_session_idx
    ON checkout_provider_sdk_audit(tenant_id, checkout_session_id, created_at);

ALTER TABLE checkout_provider_sdk_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE checkout_provider_sdk_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS checkout_provider_sdk_audit_tenant_isolation
    ON checkout_provider_sdk_audit;
CREATE POLICY checkout_provider_sdk_audit_tenant_isolation ON checkout_provider_sdk_audit
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

DROP TRIGGER IF EXISTS checkout_provider_sdk_audit_immutable
    ON checkout_provider_sdk_audit;
CREATE TRIGGER checkout_provider_sdk_audit_immutable
BEFORE UPDATE OR DELETE ON checkout_provider_sdk_audit FOR EACH ROW
EXECUTE FUNCTION elmpay_reject_mutation();
