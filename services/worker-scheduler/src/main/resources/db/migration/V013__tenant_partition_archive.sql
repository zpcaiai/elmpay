-- B13: partitioned tenant archive plane. Operational tables retain their FK-safe schemas;
-- immutable archive facts are range-partitioned and may only be detached after verified export.
CREATE TABLE IF NOT EXISTS data_table_ownership (
    table_name text PRIMARY KEY CHECK (table_name ~ '^[a-z][a-z0-9_]{1,62}$'),
    owner_service text NOT NULL CHECK (owner_service ~ '^[a-z][a-z0-9-]{1,62}$'),
    tenant_scoped boolean NOT NULL,
    mutability text NOT NULL CHECK (mutability IN ('MUTABLE', 'APPEND_ONLY')),
    partition_kind text NOT NULL CHECK (partition_kind IN ('NONE', 'RANGE', 'HASH')),
    partition_key text,
    partition_interval text,
    archive_after_days integer NOT NULL CHECK (archive_after_days > 0),
    archive_target text NOT NULL CHECK (archive_target ~ '^object-storage://'),
    configuration_digest char(64) NOT NULL CHECK (configuration_digest ~ '^[0-9a-f]{64}$'),
    registered_at timestamptz NOT NULL,
    CHECK ((partition_kind = 'NONE' AND partition_key IS NULL AND partition_interval IS NULL)
        OR (partition_kind <> 'NONE' AND partition_key IS NOT NULL
            AND partition_interval IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS tenant_archive_fact (
    tenant_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    source_table text NOT NULL CHECK (source_table ~ '^[a-z][a-z0-9_]{1,62}$'),
    source_record_id text NOT NULL,
    source_record_digest char(64) NOT NULL CHECK (source_record_digest ~ '^[0-9a-f]{64}$'),
    encrypted_payload bytea,
    payload_key_reference text CHECK (payload_key_reference IS NULL
        OR payload_key_reference ~ '^(kms|vault)://'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, occurred_at, source_table, source_record_id),
    CHECK ((encrypted_payload IS NULL) = (payload_key_reference IS NULL))
) PARTITION BY RANGE (occurred_at);

CREATE INDEX IF NOT EXISTS tenant_archive_fact_tenant_time_idx
    ON tenant_archive_fact (tenant_id, occurred_at, source_table);

ALTER TABLE tenant_archive_fact ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_fact FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_archive_fact_tenant_policy ON tenant_archive_fact;
CREATE POLICY tenant_archive_fact_tenant_policy ON tenant_archive_fact
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE TABLE IF NOT EXISTS tenant_archive_export_receipt (
    tenant_id uuid NOT NULL,
    partition_name text NOT NULL CHECK (partition_name ~ '^tenant_archive_fact_[0-9]{6}$'),
    object_uri text NOT NULL CHECK (object_uri ~ '^object-storage://'),
    manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    object_digest char(64) NOT NULL CHECK (object_digest ~ '^[0-9a-f]{64}$'),
    external_verifier_id text NOT NULL,
    external_receipt_id text NOT NULL,
    verified_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, partition_name)
);

CREATE TABLE IF NOT EXISTS tenant_partition_change (
    change_id bigserial PRIMARY KEY,
    partition_name text NOT NULL,
    action text NOT NULL CHECK (action IN ('CREATE', 'DETACH')),
    actor_id text NOT NULL,
    approver_id text,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    CHECK (approver_id IS NULL OR approver_id <> actor_id)
);

CREATE OR REPLACE FUNCTION elmpay_reject_data_governance_mutation()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    RAISE EXCEPTION 'data ownership and archive receipts are immutable';
END;
$elmpay$;

DROP TRIGGER IF EXISTS data_table_ownership_no_update ON data_table_ownership;
CREATE TRIGGER data_table_ownership_no_update
BEFORE UPDATE OR DELETE ON data_table_ownership
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_data_governance_mutation();
DROP TRIGGER IF EXISTS tenant_archive_export_receipt_no_update ON tenant_archive_export_receipt;
CREATE TRIGGER tenant_archive_export_receipt_no_update
BEFORE UPDATE OR DELETE ON tenant_archive_export_receipt
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_data_governance_mutation();

REVOKE UPDATE, DELETE ON data_table_ownership FROM PUBLIC;
REVOKE UPDATE, DELETE ON tenant_archive_fact FROM PUBLIC;
REVOKE UPDATE, DELETE ON tenant_archive_export_receipt FROM PUBLIC;
