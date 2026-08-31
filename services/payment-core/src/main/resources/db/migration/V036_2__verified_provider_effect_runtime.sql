-- Durable, tenant-scoped facts used to apply verified provider callbacks.
-- This migration does not store callback bodies or provider credentials.

DO $elmpay$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'payment_attempt'::regclass
                     AND conname = 'payment_attempt_tenant_id_unique') THEN
        ALTER TABLE payment_attempt
            ADD CONSTRAINT payment_attempt_tenant_id_unique UNIQUE (tenant_id, id);
    END IF;
END;
$elmpay$;

CREATE TABLE provider_effect_expectation (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    payment_attempt_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal')),
    expected_delta_minor bigint NOT NULL CHECK (expected_delta_minor > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    business_order_digest char(64) NOT NULL
        CHECK (business_order_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, payment_attempt_id),
    FOREIGN KEY (tenant_id, payment_intent_id)
        REFERENCES payment_intent (tenant_id, id),
    FOREIGN KEY (tenant_id, payment_attempt_id)
        REFERENCES payment_attempt (tenant_id, id)
);

CREATE INDEX provider_effect_expectation_binding_idx
    ON provider_effect_expectation
       (tenant_id, project_id, provider_account_id, provider, payment_intent_id);

CREATE TABLE provider_effect_application (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal')),
    provider_event_id varchar(160) NOT NULL,
    provider_event_type varchar(160) NOT NULL,
    mapping_version varchar(64) NOT NULL,
    verification_digest char(64) NOT NULL
        CHECK (verification_digest ~ '^[0-9a-f]{64}$'),
    canonical_payload_sha256 char(64) NOT NULL
        CHECK (canonical_payload_sha256 ~ '^[0-9a-f]{64}$'),
    target_type varchar(16) NOT NULL CHECK (target_type IN ('payment', 'refund')),
    target_id uuid NOT NULL,
    outcome varchar(32) NOT NULL CHECK (outcome IN
        ('APPLIED', 'NOOP_DUPLICATE_STATE', 'NOOP_OUT_OF_ORDER', 'NOOP_OBSERVATION')),
    provider_occurred_at timestamptz NOT NULL,
    applied_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider, provider_account_id, provider_event_id)
);

CREATE INDEX provider_effect_application_target_idx
    ON provider_effect_application (tenant_id, target_type, target_id, provider_occurred_at);

CREATE TABLE provider_effect_target_clock (
    tenant_id uuid NOT NULL,
    target_type varchar(16) NOT NULL CHECK (target_type IN ('payment', 'refund')),
    target_id uuid NOT NULL,
    last_provider_occurred_at timestamptz NOT NULL,
    last_provider_event_id varchar(160) NOT NULL,
    last_effect_kind varchar(48) NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_type, target_id)
);

ALTER TABLE provider_effect_expectation ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_expectation FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_application ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_application FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_target_clock ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_target_clock FORCE ROW LEVEL SECURITY;

CREATE POLICY provider_effect_expectation_tenant_policy ON provider_effect_expectation
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY provider_effect_application_tenant_policy ON provider_effect_application
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY provider_effect_target_clock_tenant_policy ON provider_effect_target_clock
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE OR REPLACE FUNCTION elmpay_reject_provider_effect_fact_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $elmpay$
BEGIN
    RAISE EXCEPTION 'verified provider effect fact is append-only';
END;
$elmpay$;

CREATE TRIGGER provider_effect_expectation_immutable
BEFORE UPDATE OR DELETE ON provider_effect_expectation
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_provider_effect_fact_mutation();

CREATE TRIGGER provider_effect_application_immutable
BEFORE UPDATE OR DELETE ON provider_effect_application
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_provider_effect_fact_mutation();

-- Rollback: drop the two immutable triggers, three RLS tables, helper function, and
-- payment_attempt_tenant_id_unique only after no dependent release uses this contract.
