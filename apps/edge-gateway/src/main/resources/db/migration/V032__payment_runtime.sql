-- Core payment runtime schema. Monetary values are integer minor units.
CREATE TABLE IF NOT EXISTS tenant (
    id uuid PRIMARY KEY,
    code text NOT NULL UNIQUE,
    display_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'closed')),
    data_residency text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    code text NOT NULL,
    display_name text NOT NULL,
    callback_domains jsonb NOT NULL DEFAULT '[]'::jsonb,
    status text NOT NULL CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, code)
);

CREATE TABLE IF NOT EXISTS merchant (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    legal_name text NOT NULL,
    settlement_mode text NOT NULL CHECK (settlement_mode = 'direct_to_merchant'),
    status text NOT NULL CHECK (status IN ('onboarding', 'active', 'suspended', 'terminated')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS provider_account (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    project_id uuid NOT NULL REFERENCES project(id),
    merchant_id uuid NOT NULL REFERENCES merchant(id),
    provider text NOT NULL CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal', 'apple_pay')),
    provider_merchant_id text NOT NULL,
    credential_ref text NOT NULL CHECK (credential_ref ~ '^(kms|vault)://'),
    credential_version text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox', 'production')),
    status text NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, project_id, provider, environment)
);

CREATE TABLE IF NOT EXISTS provider_capability (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    provider_account_id uuid NOT NULL REFERENCES provider_account(id),
    method text NOT NULL,
    currencies text[] NOT NULL CHECK (cardinality(currencies) > 0),
    regions text[] NOT NULL CHECK (cardinality(regions) > 0),
    authorization_capture boolean NOT NULL,
    partial_capture boolean NOT NULL,
    partial_refund boolean NOT NULL,
    subscriptions boolean NOT NULL,
    version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider_account_id, method, version)
);

CREATE TABLE IF NOT EXISTS routing_rule (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    project_id uuid NOT NULL REFERENCES project(id),
    provider_account_id uuid NOT NULL REFERENCES provider_account(id),
    priority integer NOT NULL CHECK (priority >= 0),
    min_amount_minor bigint NOT NULL CHECK (min_amount_minor >= 0),
    max_amount_minor bigint NOT NULL CHECK (max_amount_minor >= min_amount_minor),
    enabled boolean NOT NULL DEFAULT false,
    version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, project_id, provider_account_id, version)
);

CREATE TABLE IF NOT EXISTS payment_intent (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    external_reference text NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    captured_amount_minor bigint NOT NULL DEFAULT 0 CHECK (captured_amount_minor >= 0),
    refunded_amount_minor bigint NOT NULL DEFAULT 0 CHECK (refunded_amount_minor >= 0),
    state text NOT NULL CHECK (state IN
        ('created', 'requires_action', 'authorized', 'captured', 'failed', 'canceled', 'expired')),
    allowed_methods text[] NOT NULL CHECK (cardinality(allowed_methods) > 0),
    confirmation_mode text NOT NULL CHECK (confirmation_mode IN ('automatic', 'manual_capture')),
    region text NOT NULL,
    idempotency_key text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    CHECK (captured_amount_minor <= amount_minor),
    CHECK (refunded_amount_minor <= captured_amount_minor),
    UNIQUE (tenant_id, project_id, external_reference),
    UNIQUE (tenant_id, project_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS payment_attempt (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL REFERENCES payment_intent(id),
    provider_account_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal', 'apple_pay')),
    operation text NOT NULL CHECK (operation IN ('payment', 'capture', 'cancel', 'query')),
    sequence integer NOT NULL CHECK (sequence > 0),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key text NOT NULL,
    state text NOT NULL CHECK (state IN ('initiated', 'pending', 'succeeded', 'failed', 'unknown')),
    outcome_class text CHECK (outcome_class IN
        ('succeeded', 'failed_final', 'failed_retryable', 'unknown')),
    response_digest char(64),
    provider_request_id text,
    provider_transaction_id text,
    provider_code_namespace text,
    provider_code text,
    started_at timestamptz NOT NULL,
    settled_at timestamptz,
    UNIQUE (tenant_id, payment_intent_id, sequence),
    UNIQUE (tenant_id, payment_intent_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS payment_attempt_provider_transaction_unique
    ON payment_attempt(provider, provider_transaction_id)
    WHERE provider_transaction_id IS NOT NULL AND operation = 'payment';

CREATE TABLE IF NOT EXISTS idempotency_record (
    tenant_id uuid NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash char(64) NOT NULL,
    state text NOT NULL CHECK (state IN ('IN_PROGRESS', 'COMPLETED', 'UNKNOWN')),
    owner_token text NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    unknown_reason text,
    response_status integer,
    response_content_type text,
    response_body bytea,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS outbox_event (
    sequence_no bigserial PRIMARY KEY,
    id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL,
    event_version integer NOT NULL CHECK (event_version > 0),
    payload jsonb NOT NULL,
    correlation_id text NOT NULL,
    created_at timestamptz NOT NULL,
    published_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_event (
    sequence_no bigserial PRIMARY KEY,
    id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    reason text,
    ticket_id text,
    before_digest char(64) NOT NULL,
    after_digest char(64) NOT NULL,
    correlation_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    previous_hash text NOT NULL,
    chain_hash char(64) NOT NULL UNIQUE
);

-- Expand an older generated B00 schema without destructive replacement.
ALTER TABLE provider_account ADD COLUMN IF NOT EXISTS project_id uuid;
ALTER TABLE provider_account ADD COLUMN IF NOT EXISTS credential_version text;
ALTER TABLE payment_intent ADD COLUMN IF NOT EXISTS allowed_methods text[];
ALTER TABLE payment_intent ADD COLUMN IF NOT EXISTS confirmation_mode text;
ALTER TABLE payment_intent ADD COLUMN IF NOT EXISTS region text;
ALTER TABLE payment_intent ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 0;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS operation text;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS sequence integer;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS idempotency_key text;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS outcome_class text;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS response_digest char(64);
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS provider_request_id text;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS provider_code_namespace text;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS provider_code text;

CREATE INDEX IF NOT EXISTS payment_intent_tenant_lookup
    ON payment_intent(tenant_id, id);
CREATE INDEX IF NOT EXISTS payment_attempt_intent_lookup
    ON payment_attempt(tenant_id, payment_intent_id, sequence);
CREATE INDEX IF NOT EXISTS outbox_unpublished_lookup
    ON outbox_event(sequence_no) WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS idempotency_expiry_lookup
    ON idempotency_record(expires_at);

CREATE OR REPLACE FUNCTION elmpay_protect_intent_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    IF NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id
       OR NEW.merchant_id <> OLD.merchant_id
       OR NEW.external_reference <> OLD.external_reference
       OR NEW.amount_minor <> OLD.amount_minor OR NEW.currency <> OLD.currency
       OR NEW.allowed_methods <> OLD.allowed_methods
       OR NEW.confirmation_mode <> OLD.confirmation_mode OR NEW.region <> OLD.region
       OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.expires_at <> OLD.expires_at
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'payment intent immutable snapshot cannot change';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'payment intent version must advance exactly once';
    END IF;
    RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS payment_intent_snapshot_guard ON payment_intent;
CREATE TRIGGER payment_intent_snapshot_guard
BEFORE UPDATE ON payment_intent FOR EACH ROW EXECUTE FUNCTION elmpay_protect_intent_snapshot();

CREATE OR REPLACE FUNCTION elmpay_protect_final_attempt()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    IF OLD.state IN ('succeeded', 'failed') THEN
        RAISE EXCEPTION 'final payment attempt is immutable';
    END IF;
    IF NEW.request_digest <> OLD.request_digest OR NEW.operation <> OLD.operation
       OR NEW.sequence <> OLD.sequence OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.provider_account_id <> OLD.provider_account_id THEN
        RAISE EXCEPTION 'payment attempt request snapshot is immutable';
    END IF;
    RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS payment_attempt_final_guard ON payment_attempt;
CREATE TRIGGER payment_attempt_final_guard
BEFORE UPDATE ON payment_attempt FOR EACH ROW EXECUTE FUNCTION elmpay_protect_final_attempt();

CREATE OR REPLACE FUNCTION elmpay_reject_mutation()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    RAISE EXCEPTION 'append-only financial record cannot be changed';
END;
$elmpay$;

DROP TRIGGER IF EXISTS audit_event_append_only ON audit_event;
CREATE TRIGGER audit_event_append_only
BEFORE UPDATE OR DELETE ON audit_event FOR EACH ROW EXECUTE FUNCTION elmpay_reject_mutation();

ALTER TABLE project ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_capability ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;

ALTER TABLE project FORCE ROW LEVEL SECURITY;
ALTER TABLE merchant FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_account FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_capability FORCE ROW LEVEL SECURITY;
ALTER TABLE routing_rule FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_intent FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_attempt FORCE ROW LEVEL SECURITY;
ALTER TABLE idempotency_record FORCE ROW LEVEL SECURITY;
ALTER TABLE outbox_event FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS project_tenant_policy ON project;
CREATE POLICY project_tenant_policy ON project
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS merchant_tenant_policy ON merchant;
CREATE POLICY merchant_tenant_policy ON merchant
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS provider_account_tenant_policy ON provider_account;
CREATE POLICY provider_account_tenant_policy ON provider_account
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS provider_capability_tenant_policy ON provider_capability;
CREATE POLICY provider_capability_tenant_policy ON provider_capability
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS routing_rule_tenant_policy ON routing_rule;
CREATE POLICY routing_rule_tenant_policy ON routing_rule
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS payment_intent_tenant_policy ON payment_intent;
CREATE POLICY payment_intent_tenant_policy ON payment_intent
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS payment_attempt_tenant_policy ON payment_attempt;
CREATE POLICY payment_attempt_tenant_policy ON payment_attempt
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS idempotency_record_tenant_policy ON idempotency_record;
CREATE POLICY idempotency_record_tenant_policy ON idempotency_record
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS outbox_event_tenant_policy ON outbox_event;
CREATE POLICY outbox_event_tenant_policy ON outbox_event
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
DROP POLICY IF EXISTS audit_event_tenant_policy ON audit_event;
CREATE POLICY audit_event_tenant_policy ON audit_event
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
