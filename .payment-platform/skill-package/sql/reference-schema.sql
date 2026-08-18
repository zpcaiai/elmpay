-- Reference schema for PostgreSQL 18.x. Amounts are integer minor units.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
  status text NOT NULL CHECK (status IN ('pending','active','suspended','closed')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  slug text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('sandbox','production')),
  status text NOT NULL CHECK (status IN ('active','suspended','closed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, slug, environment)
);

CREATE TABLE merchant_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  project_id uuid NOT NULL REFERENCES projects(id),
  provider text NOT NULL CHECK (provider IN ('wechat','alipay','stripe','paypal','apple_pay')),
  provider_merchant_ref text NOT NULL,
  credential_ref text NOT NULL,
  credential_version text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','active','rotating','suspended','closed')),
  config_version bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, provider, provider_merchant_ref)
);

CREATE TABLE payment_intents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  project_id uuid NOT NULL REFERENCES projects(id),
  business_order_no text NOT NULL,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  capture_method text NOT NULL CHECK (capture_method IN ('automatic','manual')),
  status text NOT NULL CHECK (status IN ('requires_payment_method','requires_confirmation','requires_action','processing','requires_capture','succeeded','failed','canceled')),
  amount_captured_minor bigint NOT NULL DEFAULT 0 CHECK (amount_captured_minor >= 0),
  amount_refunded_minor bigint NOT NULL DEFAULT 0 CHECK (amount_refunded_minor >= 0),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, business_order_no),
  CHECK (amount_captured_minor <= amount_minor),
  CHECK (amount_refunded_minor <= amount_captured_minor)
);

CREATE TABLE payment_attempts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  project_id uuid NOT NULL REFERENCES projects(id),
  payment_intent_id uuid NOT NULL REFERENCES payment_intents(id),
  merchant_account_id uuid NOT NULL REFERENCES merchant_accounts(id),
  provider text NOT NULL,
  provider_request_id text NOT NULL,
  provider_payment_id text,
  idempotency_key text NOT NULL,
  request_hash char(64) NOT NULL,
  status text NOT NULL CHECK (status IN ('created','sent','acknowledged','pending_external','succeeded','failed','unknown')),
  error_class text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (merchant_account_id, provider_request_id),
  UNIQUE (project_id, idempotency_key)
);

CREATE TABLE provider_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  project_id uuid NOT NULL REFERENCES projects(id),
  merchant_account_id uuid NOT NULL REFERENCES merchant_accounts(id),
  provider text NOT NULL,
  provider_event_id text NOT NULL,
  signature_key_id text NOT NULL,
  payload_sha256 char(64) NOT NULL,
  verified_at timestamptz NOT NULL,
  processed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (merchant_account_id, provider_event_id)
);

CREATE TABLE idempotency_records (
  project_id uuid NOT NULL REFERENCES projects(id),
  operation text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash char(64) NOT NULL,
  response_status integer,
  response_body jsonb,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (project_id, operation, idempotency_key)
);

CREATE TABLE refunds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  project_id uuid NOT NULL REFERENCES projects(id),
  payment_intent_id uuid NOT NULL REFERENCES payment_intents(id),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency char(3) NOT NULL,
  status text NOT NULL CHECK (status IN ('requested','approval_pending','processing','succeeded','partially_succeeded','failed','unknown')),
  reason text NOT NULL,
  approved_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbox_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  event_type text NOT NULL,
  event_version integer NOT NULL CHECK (event_version > 0),
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);

CREATE TABLE ledger_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  code text NOT NULL,
  currency char(3) NOT NULL,
  account_type text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, code, currency)
);

CREATE TABLE ledger_transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  source_type text NOT NULL,
  source_id uuid NOT NULL,
  currency char(3) NOT NULL,
  description text NOT NULL,
  effective_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, source_type, source_id)
);

CREATE TABLE ledger_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  transaction_id uuid NOT NULL REFERENCES ledger_transactions(id),
  account_id uuid NOT NULL REFERENCES ledger_accounts(id),
  side text NOT NULL CHECK (side IN ('debit','credit')),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION deny_ledger_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ledger history is append-only';
END $$;
CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE OR DELETE ON ledger_entries FOR EACH ROW EXECUTE FUNCTION deny_ledger_mutation();
CREATE TRIGGER ledger_transactions_no_update BEFORE UPDATE OR DELETE ON ledger_transactions FOR EACH ROW EXECUTE FUNCTION deny_ledger_mutation();

CREATE OR REPLACE FUNCTION assert_ledger_transaction_balanced(p_transaction_id uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE d bigint; c bigint;
BEGIN
  SELECT COALESCE(sum(amount_minor) FILTER (WHERE side='debit'),0),
         COALESCE(sum(amount_minor) FILTER (WHERE side='credit'),0)
    INTO d, c FROM ledger_entries WHERE transaction_id=p_transaction_id;
  IF d = 0 OR d <> c THEN RAISE EXCEPTION 'unbalanced ledger transaction %: debit %, credit %', p_transaction_id, d, c; END IF;
END $$;

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE refunds ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_projects ON projects USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_merchant_accounts ON merchant_accounts USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_payment_intents ON payment_intents USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_payment_attempts ON payment_attempts USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_provider_events ON provider_events USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY tenant_refunds ON refunds USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
