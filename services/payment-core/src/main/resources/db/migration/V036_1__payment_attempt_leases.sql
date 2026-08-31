-- B33/B36: crash-safe provider-attempt recovery leases and monotonic fencing.
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS lease_owner text;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS fencing_token bigint;
ALTER TABLE payment_attempt ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz;

-- The existing final-attempt trigger rejects every update to a final row. DDL and backfill run in
-- this migration's single transaction while the table lock is held, then the guard is restored.
DROP TRIGGER IF EXISTS payment_attempt_final_guard ON payment_attempt;

UPDATE payment_attempt
   SET lease_owner = COALESCE(lease_owner, 'legacy:' || id::text),
       fencing_token = COALESCE(fencing_token, 1),
       lease_expires_at = COALESCE(lease_expires_at, settled_at, started_at)
 WHERE lease_owner IS NULL OR fencing_token IS NULL OR lease_expires_at IS NULL;

CREATE TRIGGER payment_attempt_final_guard
BEFORE UPDATE ON payment_attempt FOR EACH ROW EXECUTE FUNCTION elmpay_protect_final_attempt();

ALTER TABLE payment_attempt ALTER COLUMN lease_owner SET NOT NULL;
ALTER TABLE payment_attempt ALTER COLUMN fencing_token SET NOT NULL;
ALTER TABLE payment_attempt ALTER COLUMN lease_expires_at SET NOT NULL;

ALTER TABLE payment_attempt
    DROP CONSTRAINT IF EXISTS payment_attempt_lease_owner_check;
ALTER TABLE payment_attempt
    ADD CONSTRAINT payment_attempt_lease_owner_check
    CHECK (length(lease_owner) BETWEEN 1 AND 128);
ALTER TABLE payment_attempt
    DROP CONSTRAINT IF EXISTS payment_attempt_fencing_token_check;
ALTER TABLE payment_attempt
    ADD CONSTRAINT payment_attempt_fencing_token_check CHECK (fencing_token > 0);
ALTER TABLE payment_attempt
    DROP CONSTRAINT IF EXISTS payment_attempt_lease_time_check;
ALTER TABLE payment_attempt
    ADD CONSTRAINT payment_attempt_lease_time_check CHECK (lease_expires_at >= started_at);

CREATE INDEX IF NOT EXISTS payment_attempt_recovery_lease_idx
    ON payment_attempt (tenant_id, payment_intent_id, lease_expires_at, sequence DESC)
    WHERE operation <> 'query' AND state IN ('initiated', 'pending', 'unknown');
