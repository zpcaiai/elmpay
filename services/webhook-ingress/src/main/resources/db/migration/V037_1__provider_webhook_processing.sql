ALTER TABLE provider_webhook_inbox
    ADD COLUMN canonical_payload_sha256 CHAR(64),
    ADD COLUMN verification_digest CHAR(64),
    ADD COLUMN next_attempt_at TIMESTAMPTZ,
    ADD COLUMN lease_owner VARCHAR(128),
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN fencing_token BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN terminal_failure BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN last_attempt_at TIMESTAMPTZ,
    ADD COLUMN diagnostic_summary VARCHAR(512);

-- Rows accepted before immutable verifier digests existed cannot be dispatched safely. Keep
-- completed rows as historical facts, and quarantine every unfinished legacy row for explicit
-- re-verification instead of manufacturing verification evidence during migration.
UPDATE provider_webhook_inbox
   SET processing_status = 'FAILED',
       terminal_failure = TRUE,
       lease_owner = NULL,
       lease_expires_at = NULL,
       next_attempt_at = NULL,
       last_error_code = 'LEGACY_VERIFICATION_DIGEST_MISSING',
       diagnostic_summary = 'legacy row requires provider webhook re-verification'
 WHERE processing_status <> 'PROCESSED';

ALTER TABLE provider_webhook_inbox
    ADD CONSTRAINT provider_webhook_inbox_tenant_inbox_uk UNIQUE (tenant_id, inbox_id),
    ADD CONSTRAINT provider_webhook_inbox_canonical_digest_ck CHECK (
        canonical_payload_sha256 IS NULL
        OR canonical_payload_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT provider_webhook_inbox_verification_digest_ck CHECK (
        verification_digest IS NULL
        OR verification_digest ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT provider_webhook_inbox_digest_pair_ck CHECK (
        (canonical_payload_sha256 IS NULL) = (verification_digest IS NULL)),
    ADD CONSTRAINT provider_webhook_inbox_dispatchable_digest_ck CHECK (
        verification_digest IS NOT NULL
        OR processing_status = 'PROCESSED'
        OR terminal_failure),
    ADD CONSTRAINT provider_webhook_inbox_lease_ck CHECK (
        (processing_status = 'PROCESSING'
         AND lease_owner IS NOT NULL
         AND lease_expires_at IS NOT NULL)
        OR
        (processing_status <> 'PROCESSING'
         AND lease_owner IS NULL
         AND lease_expires_at IS NULL)),
    ADD CONSTRAINT provider_webhook_inbox_fence_ck CHECK (fencing_token >= 0),
    ADD CONSTRAINT provider_webhook_inbox_terminal_ck CHECK (
        NOT terminal_failure OR processing_status = 'FAILED');

DROP INDEX provider_webhook_inbox_pending_idx;
CREATE INDEX provider_webhook_inbox_due_idx
    ON provider_webhook_inbox (
        tenant_id,
        COALESCE(next_attempt_at, received_at),
        inbox_id)
    WHERE terminal_failure = FALSE
      AND processing_status IN ('VERIFIED', 'FAILED');

CREATE INDEX provider_webhook_inbox_stale_lease_idx
    ON provider_webhook_inbox (tenant_id, lease_expires_at, inbox_id)
    WHERE terminal_failure = FALSE
      AND processing_status = 'PROCESSING';

CREATE TABLE provider_webhook_effect_commit (
    tenant_id VARCHAR(64) NOT NULL,
    inbox_id BIGINT NOT NULL,
    verification_digest CHAR(64) NOT NULL
        CHECK (verification_digest ~ '^[0-9a-f]{64}$'),
    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, inbox_id),
    FOREIGN KEY (tenant_id, inbox_id)
        REFERENCES provider_webhook_inbox (tenant_id, inbox_id)
);

ALTER TABLE provider_webhook_effect_commit ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_webhook_effect_commit FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_webhook_effect_commit_tenant_policy
    ON provider_webhook_effect_commit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE FUNCTION elmpay_reject_webhook_effect_commit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $elmpay$
BEGIN
    RAISE EXCEPTION 'provider_webhook_effect_commit is append-only';
END;
$elmpay$;

CREATE TRIGGER provider_webhook_effect_commit_immutable
BEFORE UPDATE OR DELETE ON provider_webhook_effect_commit
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_webhook_effect_commit_mutation();

-- Rollback: drop the effect-commit trigger/function/table and due indexes, then remove the
-- processing columns and constraints. Quarantined legacy rows intentionally require review.
