-- Durable B64/B65 refund runtime. Amounts are integer minor units.
-- V032 must run first so payment_intent and outbox_event exist.
CREATE TABLE IF NOT EXISTS refund (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid,
    payment_intent_id uuid NOT NULL REFERENCES payment_intent(id),
    provider_account_id uuid,
    provider text,
    provider_payment_id text,
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    reason text NOT NULL,
    state text NOT NULL,
    risk_decision text,
    risk_context_digest char(64),
    idempotency_key text NOT NULL,
    request_digest char(64),
    requester_id text,
    approved_by text,
    approval_reason text,
    approval_ticket_id text,
    provider_refund_id text,
    provider_outcome_digest char(64),
    failure_code text,
    correlation_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0)
);

-- Additive expansion of the generated canonical B00 refund table.
ALTER TABLE refund ADD COLUMN IF NOT EXISTS project_id uuid;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS provider_account_id uuid;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS provider_payment_id text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS risk_decision text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS risk_context_digest char(64);
ALTER TABLE refund ADD COLUMN IF NOT EXISTS request_digest char(64);
ALTER TABLE refund ADD COLUMN IF NOT EXISTS requester_id text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS approval_reason text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS approval_ticket_id text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS provider_refund_id text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS provider_outcome_digest char(64);
ALTER TABLE refund ADD COLUMN IF NOT EXISTS failure_code text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS correlation_id text;
ALTER TABLE refund ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 0;

-- Bind financial facts to the same tenant as their payment intent. The UUID primary
-- key alone is not sufficient for a tenant-scoped foreign-key proof.
DO $elmpay$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'payment_intent'::regclass
                     AND conname = 'payment_intent_tenant_id_unique') THEN
        ALTER TABLE payment_intent
            ADD CONSTRAINT payment_intent_tenant_id_unique UNIQUE (tenant_id, id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'refund'::regclass
                     AND conname = 'refund_tenant_id_unique') THEN
        ALTER TABLE refund
            ADD CONSTRAINT refund_tenant_id_unique UNIQUE (tenant_id, id);
    END IF;
END;
$elmpay$;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_payment_intent_id_fkey;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_payment_tenant_fk;
ALTER TABLE refund ADD CONSTRAINT refund_payment_tenant_fk
    FOREIGN KEY (tenant_id, payment_intent_id)
    REFERENCES payment_intent (tenant_id, id);

ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_reason_enum;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_state_enum;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_reason_check;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_state_check;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_provider_check;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_risk_decision_check;
ALTER TABLE refund DROP CONSTRAINT IF EXISTS refund_four_eyes_check;

ALTER TABLE refund ADD CONSTRAINT refund_reason_check CHECK (reason IN
    ('customer_request', 'duplicate', 'fraudulent', 'service_failure', 'other',
     'requested_by_customer', 'dispute'));
ALTER TABLE refund ADD CONSTRAINT refund_state_check CHECK (state IN
    ('requested', 'approved', 'approval_pending', 'processing', 'unknown',
     'succeeded', 'partially_succeeded', 'failed', 'canceled'));
ALTER TABLE refund ADD CONSTRAINT refund_provider_check CHECK
    (provider IS NULL OR provider IN ('wechat', 'alipay', 'stripe', 'paypal', 'apple_pay'));
ALTER TABLE refund ADD CONSTRAINT refund_risk_decision_check CHECK
    (risk_decision IS NULL OR risk_decision IN ('auto_approve', 'require_approval', 'deny'));
ALTER TABLE refund ADD CONSTRAINT refund_four_eyes_check CHECK
    (approved_by IS NULL OR requester_id IS NULL OR approved_by <> requester_id);

CREATE UNIQUE INDEX IF NOT EXISTS refund_tenant_idempotency_unique
    ON refund(tenant_id, idempotency_key);
CREATE INDEX IF NOT EXISTS refund_payment_reservation_lookup
    ON refund(tenant_id, payment_intent_id, state);
CREATE UNIQUE INDEX IF NOT EXISTS refund_provider_reference_unique
    ON refund(provider, provider_refund_id)
    WHERE provider_refund_id IS NOT NULL AND state = 'succeeded';

CREATE TABLE IF NOT EXISTS refund_action_receipt (
    tenant_id uuid NOT NULL,
    refund_id uuid NOT NULL REFERENCES refund(id),
    operation text NOT NULL CHECK (operation IN ('REFUND_APPROVE', 'REFUND_QUERY')),
    idempotency_key text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    actor_id text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    result_version bigint NOT NULL CHECK (result_version >= 0),
    completed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key)
);
ALTER TABLE refund_action_receipt DROP CONSTRAINT IF EXISTS refund_action_receipt_refund_id_fkey;
ALTER TABLE refund_action_receipt DROP CONSTRAINT IF EXISTS refund_action_receipt_refund_fk;
ALTER TABLE refund_action_receipt ADD CONSTRAINT refund_action_receipt_refund_fk
    FOREIGN KEY (tenant_id, refund_id) REFERENCES refund (tenant_id, id);
CREATE INDEX IF NOT EXISTS refund_action_receipt_refund_lookup
    ON refund_action_receipt(tenant_id, refund_id);

CREATE OR REPLACE FUNCTION elmpay_protect_refund_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.payment_intent_id IS DISTINCT FROM OLD.payment_intent_id
       OR NEW.provider_account_id IS DISTINCT FROM OLD.provider_account_id
       OR NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.provider_payment_id IS DISTINCT FROM OLD.provider_payment_id
       OR NEW.amount_minor IS DISTINCT FROM OLD.amount_minor
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.reason IS DISTINCT FROM OLD.reason
       OR NEW.risk_decision IS DISTINCT FROM OLD.risk_decision
       OR NEW.risk_context_digest IS DISTINCT FROM OLD.risk_context_digest
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.requester_id IS DISTINCT FROM OLD.requester_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'refund request snapshot cannot change';
    END IF;
    IF OLD.state IN ('succeeded', 'failed', 'canceled') THEN
        RAISE EXCEPTION 'final refund is immutable';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'refund version must advance exactly once';
    END IF;
    RETURN NEW;
END;
$elmpay$;

DROP TRIGGER IF EXISTS refund_snapshot_guard ON refund;
CREATE TRIGGER refund_snapshot_guard
BEFORE UPDATE ON refund FOR EACH ROW EXECUTE FUNCTION elmpay_protect_refund_snapshot();

ALTER TABLE refund ENABLE ROW LEVEL SECURITY;
ALTER TABLE refund FORCE ROW LEVEL SECURITY;
ALTER TABLE refund_action_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE refund_action_receipt FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS refund_tenant_policy ON refund;
CREATE POLICY refund_tenant_policy ON refund
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS refund_action_receipt_tenant_policy ON refund_action_receipt;
CREATE POLICY refund_action_receipt_tenant_policy ON refund_action_receipt
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
