-- Durable B66-B71 commerce lifecycle. V032 must create tenant/project/outbox_event first.
-- Monetary values are integer minor units; payment instruments are opaque PSP references only.
CREATE TABLE IF NOT EXISTS commerce_action_receipt (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    resource_id uuid NOT NULL,
    actor_id text NOT NULL,
    correlation_id text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS billing_plan (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    code text NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    billing_period_seconds bigint NOT NULL CHECK (billing_period_seconds > 0),
    trial_period_seconds bigint NOT NULL CHECK (trial_period_seconds >= 0),
    metered boolean NOT NULL,
    active boolean NOT NULL DEFAULT true,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, project_id, code, version),
    UNIQUE (id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS billing_mandate (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    customer_reference text NOT NULL,
    provider text NOT NULL CHECK (provider IN ('wechat','alipay','stripe','paypal','apple_pay')),
    provider_mandate_reference text NOT NULL,
    payment_method_reference text NOT NULL CHECK
      (payment_method_reference ~ '^(psp|wallet|mandate)://[A-Za-z0-9._:/-]+$'),
    purpose text NOT NULL,
    maximum_amount_minor bigint NOT NULL CHECK (maximum_amount_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    consent_digest char(64) NOT NULL CHECK (consent_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('active','revoked')),
    consented_at timestamptz NOT NULL,
    revoked_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, project_id, provider, provider_mandate_reference),
    UNIQUE (id, tenant_id, project_id),
    CHECK ((state = 'active' AND revoked_at IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS billing_subscription (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    customer_reference text NOT NULL,
    plan_id uuid NOT NULL,
    mandate_id uuid NOT NULL,
    state text NOT NULL CHECK
      (state IN ('trialing','active','past_due','paused','canceled')),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    usage_quantity bigint NOT NULL DEFAULT 0 CHECK (usage_quantity >= 0),
    cancel_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (plan_id, tenant_id, project_id)
      REFERENCES billing_plan(id, tenant_id, project_id),
    FOREIGN KEY (mandate_id, tenant_id, project_id)
      REFERENCES billing_mandate(id, tenant_id, project_id),
    UNIQUE (id, tenant_id, project_id),
    CHECK (period_end > period_start),
    CHECK (cancel_at IS NULL OR (cancel_at >= period_start AND cancel_at <= period_end))
);

CREATE TABLE IF NOT EXISTS subscription_usage_inbox (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    quantity bigint NOT NULL CHECK (quantity > 0),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subscription_id, idempotency_key),
    FOREIGN KEY (subscription_id, tenant_id, project_id)
      REFERENCES billing_subscription(id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS subscription_billing_cycle (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    state text NOT NULL CHECK (state IN ('queued','succeeded','failed','unknown')),
    provider_result_digest char(64),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (subscription_id, tenant_id, project_id)
      REFERENCES billing_subscription(id, tenant_id, project_id),
    UNIQUE (tenant_id, subscription_id, period_start),
    UNIQUE (id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS dunning_case (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    billing_cycle_id uuid NOT NULL,
    state text NOT NULL CHECK
      (state IN ('scheduled','waiting_provider_query','recovered','exhausted','paused')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    maximum_attempts integer NOT NULL CHECK (maximum_attempts > 0),
    next_attempt_at timestamptz,
    grace_ends_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (subscription_id, tenant_id, project_id)
      REFERENCES billing_subscription(id, tenant_id, project_id),
    FOREIGN KEY (billing_cycle_id, tenant_id, project_id)
      REFERENCES subscription_billing_cycle(id, tenant_id, project_id),
    UNIQUE (tenant_id, billing_cycle_id),
    UNIQUE (id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS billing_adjustment (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('plan_change','cancellation','credit')),
    old_plan_id uuid,
    new_plan_id uuid,
    old_unused_credit_minor bigint NOT NULL CHECK (old_unused_credit_minor >= 0),
    new_remaining_charge_minor bigint NOT NULL CHECK (new_remaining_charge_minor >= 0),
    net_debit_minor bigint NOT NULL,
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    remaining_seconds bigint NOT NULL CHECK (remaining_seconds >= 0),
    period_seconds bigint NOT NULL CHECK (period_seconds > 0),
    reason text NOT NULL,
    actor_id text NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (subscription_id, tenant_id, project_id)
      REFERENCES billing_subscription(id, tenant_id, project_id),
    UNIQUE (id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS provider_dispute (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('wechat','alipay','stripe','paypal','apple_pay')),
    provider_dispute_id text NOT NULL,
    payment_intent_id uuid NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    response_deadline timestamptz NOT NULL,
    state text NOT NULL CHECK
      (state IN ('open','evidence_submitted','won','lost','accepted','appealed')),
    financial_effect_state text NOT NULL CHECK
      (financial_effect_state IN ('pending','posted','reversed')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, payment_intent_id)
      REFERENCES payment_intent(tenant_id, id),
    UNIQUE (tenant_id, project_id, provider, provider_dispute_id),
    UNIQUE (id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS dispute_event_inbox (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider text NOT NULL,
    provider_event_id text NOT NULL,
    provider_dispute_id text NOT NULL,
    payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    dispute_id uuid NOT NULL,
    received_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider, provider_event_id),
    FOREIGN KEY (dispute_id, tenant_id, project_id)
      REFERENCES provider_dispute(id, tenant_id, project_id)
);

CREATE TABLE IF NOT EXISTS dispute_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    dispute_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    object_digest char(64) NOT NULL CHECK (object_digest ~ '^[0-9a-f]{64}$'),
    media_type text NOT NULL,
    object_reference text NOT NULL CHECK (object_reference ~ '^(s3|gcs|azure|vault)://'),
    submitted_by text NOT NULL,
    submitted_at timestamptz NOT NULL,
    FOREIGN KEY (dispute_id, tenant_id, project_id)
      REFERENCES provider_dispute(id, tenant_id, project_id),
    UNIQUE (tenant_id, dispute_id, revision)
);

CREATE INDEX IF NOT EXISTS billing_subscription_due_idx
  ON billing_subscription(tenant_id, period_end, id) WHERE state IN ('trialing','active');
CREATE INDEX IF NOT EXISTS dunning_case_due_idx
  ON dunning_case(tenant_id, next_attempt_at, id) WHERE state = 'scheduled';
CREATE INDEX IF NOT EXISTS provider_dispute_deadline_idx
  ON provider_dispute(tenant_id, response_deadline, id)
  WHERE state IN ('open','evidence_submitted','appealed');

CREATE OR REPLACE FUNCTION elmpay_immutable_commerce_history()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  RAISE EXCEPTION 'commerce history is immutable' USING ERRCODE = '55000';
END;
$elmpay$;

DROP TRIGGER IF EXISTS subscription_usage_immutable ON subscription_usage_inbox;
CREATE TRIGGER subscription_usage_immutable BEFORE UPDATE OR DELETE ON subscription_usage_inbox
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();
DROP TRIGGER IF EXISTS billing_cycle_no_delete ON subscription_billing_cycle;
CREATE TRIGGER billing_cycle_no_delete BEFORE DELETE ON subscription_billing_cycle
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();
DROP TRIGGER IF EXISTS billing_adjustment_immutable ON billing_adjustment;
CREATE TRIGGER billing_adjustment_immutable BEFORE UPDATE OR DELETE ON billing_adjustment
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();
DROP TRIGGER IF EXISTS dispute_event_immutable ON dispute_event_inbox;
CREATE TRIGGER dispute_event_immutable BEFORE UPDATE OR DELETE ON dispute_event_inbox
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();
DROP TRIGGER IF EXISTS dispute_evidence_immutable ON dispute_evidence;
CREATE TRIGGER dispute_evidence_immutable BEFORE UPDATE OR DELETE ON dispute_evidence
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();
DROP TRIGGER IF EXISTS commerce_receipt_immutable ON commerce_action_receipt;
CREATE TRIGGER commerce_receipt_immutable BEFORE UPDATE OR DELETE ON commerce_action_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_commerce_history();

DO $elmpay$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'commerce_action_receipt','billing_plan','billing_mandate','billing_subscription',
    'subscription_usage_inbox','subscription_billing_cycle','dunning_case',
    'billing_adjustment','provider_dispute','dispute_event_inbox','dispute_evidence'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_tenant_policy', table_name);
    EXECUTE format(
      'CREATE POLICY %I ON %I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)',
      table_name || '_tenant_policy', table_name);
  END LOOP;
END;
$elmpay$;

REVOKE UPDATE, DELETE ON commerce_action_receipt, subscription_usage_inbox,
  billing_adjustment, dispute_event_inbox, dispute_evidence FROM PUBLIC;
