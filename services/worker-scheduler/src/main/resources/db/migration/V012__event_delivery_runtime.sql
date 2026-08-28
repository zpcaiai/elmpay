-- B12 durable event delivery. V032__payment_runtime.sql must create outbox_event first.
ALTER TABLE outbox_event
    ADD COLUMN IF NOT EXISTS delivery_attempts integer NOT NULL DEFAULT 0
        CHECK (delivery_attempts >= 0),
    ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz,
    ADD COLUMN IF NOT EXISTS lease_owner text,
    ADD COLUMN IF NOT EXISTS lease_until timestamptz,
    ADD COLUMN IF NOT EXISTS fencing_token bigint NOT NULL DEFAULT 0
        CHECK (fencing_token >= 0),
    ADD COLUMN IF NOT EXISTS last_error_code text;

UPDATE outbox_event
   SET next_attempt_at = created_at
 WHERE next_attempt_at IS NULL;

ALTER TABLE outbox_event
    ALTER COLUMN next_attempt_at SET NOT NULL,
    ALTER COLUMN next_attempt_at SET DEFAULT now();

CREATE INDEX IF NOT EXISTS outbox_event_delivery_due_idx
    ON outbox_event (tenant_id, next_attempt_at, sequence_no)
    WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS consumer_event_inbox (
    tenant_id uuid NOT NULL,
    consumer_name text NOT NULL,
    source_event_id uuid NOT NULL,
    project_id uuid NOT NULL,
    payload_sha256 char(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('processing', 'processed')),
    lease_owner text,
    lease_until timestamptz,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    delivery_attempts integer NOT NULL CHECK (delivery_attempts > 0),
    next_attempt_at timestamptz NOT NULL,
    last_error_code text,
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    PRIMARY KEY (tenant_id, consumer_name, source_event_id),
    CHECK ((state = 'processed' AND processed_at IS NOT NULL
            AND lease_owner IS NULL AND lease_until IS NULL)
        OR (state = 'processing' AND processed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS consumer_event_inbox_retry_idx
    ON consumer_event_inbox (tenant_id, consumer_name, next_attempt_at)
    WHERE state = 'processing';

ALTER TABLE consumer_event_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumer_event_inbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS consumer_event_inbox_tenant_policy ON consumer_event_inbox;
CREATE POLICY consumer_event_inbox_tenant_policy ON consumer_event_inbox
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- Rollback is deliberately explicit and non-destructive by default:
-- DROP POLICY consumer_event_inbox_tenant_policy ON consumer_event_inbox;
-- DROP TABLE consumer_event_inbox;
-- DROP INDEX outbox_event_delivery_due_idx;
-- ALTER TABLE outbox_event DROP COLUMN last_error_code, DROP COLUMN fencing_token,
--   DROP COLUMN lease_until, DROP COLUMN lease_owner, DROP COLUMN next_attempt_at,
--   DROP COLUMN delivery_attempts;
