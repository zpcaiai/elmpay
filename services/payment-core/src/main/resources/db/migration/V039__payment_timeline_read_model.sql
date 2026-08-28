-- B39 durable, rebuildable payment status and timeline projection.
CREATE TABLE IF NOT EXISTS payment_projection_checkpoint (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    projector_name text NOT NULL,
    last_sequence_no bigint NOT NULL DEFAULT 0 CHECK (last_sequence_no >= 0),
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, projector_name)
);

CREATE TABLE IF NOT EXISTS payment_status_read_model (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    state text NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency char(3),
    captured_amount_minor bigint NOT NULL CHECK (captured_amount_minor >= 0),
    refunded_amount_minor bigint NOT NULL CHECK (refunded_amount_minor >= 0),
    provider text,
    provider_transaction_id text,
    provider_status text,
    risk_outcome text,
    last_sequence_no bigint NOT NULL CHECK (last_sequence_no > 0),
    generation bigint NOT NULL CHECK (generation > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, payment_intent_id),
    CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
    CHECK (refunded_amount_minor <= captured_amount_minor),
    CHECK (captured_amount_minor <= amount_minor)
);

CREATE TABLE IF NOT EXISTS payment_timeline_event (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    sequence_no bigint NOT NULL CHECK (sequence_no > 0),
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    event_version integer NOT NULL CHECK (event_version > 0),
    provider text,
    provider_transaction_id text,
    risk_outcome text,
    correlation_id text NOT NULL,
    payload jsonb NOT NULL,
    payload_sha256 char(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, generation, sequence_no),
    UNIQUE (tenant_id, project_id, generation, event_id)
);

CREATE INDEX IF NOT EXISTS payment_timeline_intent_idx
    ON payment_timeline_event
       (tenant_id, project_id, payment_intent_id, generation, sequence_no);
CREATE INDEX IF NOT EXISTS payment_status_updated_idx
    ON payment_status_read_model (tenant_id, project_id, updated_at, payment_intent_id);

ALTER TABLE payment_projection_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_projection_checkpoint FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_status_read_model ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_status_read_model FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_timeline_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_timeline_event FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS payment_projection_checkpoint_tenant_policy
    ON payment_projection_checkpoint;
CREATE POLICY payment_projection_checkpoint_tenant_policy ON payment_projection_checkpoint
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
DROP POLICY IF EXISTS payment_status_read_model_tenant_policy ON payment_status_read_model;
CREATE POLICY payment_status_read_model_tenant_policy ON payment_status_read_model
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
DROP POLICY IF EXISTS payment_timeline_event_tenant_policy ON payment_timeline_event;
CREATE POLICY payment_timeline_event_tenant_policy ON payment_timeline_event
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Rollback: drop the three read-model tables. Source payment facts and outbox_event are untouched.
