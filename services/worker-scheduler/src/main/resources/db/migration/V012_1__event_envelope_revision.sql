-- B12/B13 production event envelope and database-owned aggregate revision.
-- V012__event_delivery_runtime.sql and V032__payment_runtime.sql must run first.

CREATE TABLE IF NOT EXISTS event_aggregate_revision (
    tenant_id uuid NOT NULL,
    aggregate_type text NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    aggregate_id uuid NOT NULL,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, aggregate_type, aggregate_id)
);

ALTER TABLE outbox_event
    ADD COLUMN IF NOT EXISTS aggregate_revision bigint,
    ADD COLUMN IF NOT EXISTS occurred_at timestamptz,
    ADD COLUMN IF NOT EXISTS recorded_at timestamptz,
    ADD COLUMN IF NOT EXISTS trace_id text;

-- Existing rows get a deterministic order based on their database sequence, never wall clock.
WITH ranked AS (
    SELECT sequence_no,
           row_number() OVER (
               PARTITION BY tenant_id, aggregate_type, aggregate_id
               ORDER BY sequence_no
           ) AS revision
      FROM outbox_event
)
UPDATE outbox_event AS target
   SET aggregate_revision = ranked.revision
  FROM ranked
 WHERE target.sequence_no = ranked.sequence_no;

UPDATE outbox_event
   SET occurred_at = COALESCE(occurred_at, created_at),
       recorded_at = COALESCE(recorded_at, created_at),
       trace_id = CASE
           WHEN trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN trace_id
           WHEN correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN correlation_id
           ELSE id::text
       END;

ALTER TABLE outbox_event
    ALTER COLUMN aggregate_revision SET NOT NULL,
    ALTER COLUMN occurred_at SET NOT NULL,
    ALTER COLUMN recorded_at SET NOT NULL,
    ALTER COLUMN trace_id SET NOT NULL;

ALTER TABLE outbox_event DROP CONSTRAINT IF EXISTS outbox_event_revision_positive;
ALTER TABLE outbox_event ADD CONSTRAINT outbox_event_revision_positive
    CHECK (aggregate_revision > 0);
ALTER TABLE outbox_event DROP CONSTRAINT IF EXISTS outbox_event_recorded_after_occurred;
ALTER TABLE outbox_event ADD CONSTRAINT outbox_event_recorded_after_occurred
    CHECK (occurred_at <= recorded_at + interval '5 minutes');
ALTER TABLE outbox_event DROP CONSTRAINT IF EXISTS outbox_event_trace_id_format;
ALTER TABLE outbox_event ADD CONSTRAINT outbox_event_trace_id_format
    CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');

CREATE UNIQUE INDEX IF NOT EXISTS outbox_event_tenant_aggregate_revision_unique
    ON outbox_event (tenant_id, aggregate_type, aggregate_id, aggregate_revision);
CREATE INDEX IF NOT EXISTS outbox_event_unpublished_aggregate_revision_idx
    ON outbox_event (tenant_id, aggregate_type, aggregate_id, aggregate_revision)
    WHERE published_at IS NULL;

INSERT INTO event_aggregate_revision
  (tenant_id, aggregate_type, aggregate_id, current_revision, updated_at)
SELECT tenant_id, aggregate_type, aggregate_id, max(aggregate_revision), max(recorded_at)
  FROM outbox_event
 GROUP BY tenant_id, aggregate_type, aggregate_id
ON CONFLICT (tenant_id, aggregate_type, aggregate_id) DO UPDATE
   SET current_revision = GREATEST(event_aggregate_revision.current_revision,
                                   EXCLUDED.current_revision),
       updated_at = GREATEST(event_aggregate_revision.updated_at, EXCLUDED.updated_at);

ALTER TABLE consumer_event_inbox
    ADD COLUMN IF NOT EXISTS event_name text,
    ADD COLUMN IF NOT EXISTS event_version integer,
    ADD COLUMN IF NOT EXISTS aggregate_type text,
    ADD COLUMN IF NOT EXISTS aggregate_id uuid,
    ADD COLUMN IF NOT EXISTS aggregate_revision bigint,
    ADD COLUMN IF NOT EXISTS occurred_at timestamptz,
    ADD COLUMN IF NOT EXISTS recorded_at timestamptz,
    ADD COLUMN IF NOT EXISTS trace_id text;

UPDATE consumer_event_inbox AS inbox
   SET event_name = COALESCE(inbox.event_name, source.event_type),
       event_version = COALESCE(inbox.event_version, source.event_version),
       aggregate_type = COALESCE(inbox.aggregate_type, source.aggregate_type),
       aggregate_id = COALESCE(inbox.aggregate_id, source.aggregate_id),
       aggregate_revision = COALESCE(inbox.aggregate_revision, source.aggregate_revision),
       occurred_at = COALESCE(inbox.occurred_at, source.occurred_at),
       recorded_at = COALESCE(inbox.recorded_at, source.recorded_at),
       trace_id = COALESCE(inbox.trace_id, source.trace_id)
  FROM outbox_event AS source
 WHERE source.id = inbox.source_event_id;

-- A pre-upgrade external inbox row cannot prove its original aggregate metadata. Keep it
-- explicitly legacy and non-financial rather than guessing a payment/refund identity.
UPDATE consumer_event_inbox
   SET event_name = COALESCE(event_name, 'legacy.unknown'),
       event_version = COALESCE(event_version, 1),
       aggregate_type = COALESCE(aggregate_type, 'legacy'),
       aggregate_id = COALESCE(aggregate_id, source_event_id),
       aggregate_revision = COALESCE(aggregate_revision, 1),
       occurred_at = COALESCE(occurred_at, received_at),
       recorded_at = COALESCE(recorded_at, received_at),
       trace_id = COALESCE(trace_id, source_event_id::text);

ALTER TABLE consumer_event_inbox
    ALTER COLUMN event_name SET NOT NULL,
    ALTER COLUMN event_version SET NOT NULL,
    ALTER COLUMN aggregate_type SET NOT NULL,
    ALTER COLUMN aggregate_id SET NOT NULL,
    ALTER COLUMN aggregate_revision SET NOT NULL,
    ALTER COLUMN occurred_at SET NOT NULL,
    ALTER COLUMN recorded_at SET NOT NULL,
    ALTER COLUMN trace_id SET NOT NULL;

ALTER TABLE consumer_event_inbox DROP CONSTRAINT IF EXISTS consumer_inbox_event_version_positive;
ALTER TABLE consumer_event_inbox ADD CONSTRAINT consumer_inbox_event_version_positive
    CHECK (event_version > 0);
ALTER TABLE consumer_event_inbox DROP CONSTRAINT IF EXISTS consumer_inbox_revision_positive;
ALTER TABLE consumer_event_inbox ADD CONSTRAINT consumer_inbox_revision_positive
    CHECK (aggregate_revision > 0);
CREATE UNIQUE INDEX IF NOT EXISTS consumer_inbox_aggregate_revision_unique
    ON consumer_event_inbox
       (tenant_id, consumer_name, aggregate_type, aggregate_id, aggregate_revision);

ALTER TABLE event_aggregate_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_aggregate_revision FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS event_aggregate_revision_tenant_policy ON event_aggregate_revision;
CREATE POLICY event_aggregate_revision_tenant_policy ON event_aggregate_revision
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON event_aggregate_revision FROM PUBLIC;
