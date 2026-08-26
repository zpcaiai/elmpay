-- Ledger tables intentionally use the same UUIDs, column names and enum values as
-- contracts/sql/schema.sql. Runtime-only columns are additive so this migration
-- is also safe when the generated contract schema was installed first.
CREATE TABLE IF NOT EXISTS ledger_account (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  code text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('asset','liability','revenue','expense','clearing')),
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  display_name text NOT NULL,
  created_at timestamptz NOT NULL
);
ALTER TABLE ledger_account ADD COLUMN IF NOT EXISTS display_name text;
UPDATE ledger_account SET display_name = code WHERE display_name IS NULL;
ALTER TABLE ledger_account ALTER COLUMN display_name SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ledger_account_tenant_code_currency_unique
  ON ledger_account (tenant_id, code, currency);
CREATE UNIQUE INDEX IF NOT EXISTS ledger_account_tenant_identity_unique
  ON ledger_account (id, tenant_id, currency);

CREATE TABLE IF NOT EXISTS ledger_transaction (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  source_kind text NOT NULL CHECK (source_kind IN ('payment','refund','fee','fx','dispute','adjustment','settlement')),
  source_id text NOT NULL,
  posted_at timestamptz NOT NULL,
  reason text,
  approved_by text,
  request_hash text NOT NULL,
  reversal_of uuid
);
ALTER TABLE ledger_transaction ADD COLUMN IF NOT EXISTS request_hash text;
ALTER TABLE ledger_transaction ADD COLUMN IF NOT EXISTS reversal_of uuid;
-- Contract-first installations can already contain immutable historical rows.
-- Give those rows a deterministic, explicitly legacy digest so the runtime
-- never encounters NULL evidence and never mistakes it for a replayable hash.
UPDATE ledger_transaction
   SET request_hash = 'legacy:' || encode(sha256(convert_to(concat_ws(E'\x1f',
       tenant_id::text, source_kind, source_id, posted_at::text, COALESCE(reason, '')),
       'UTF8')), 'hex')
 WHERE request_hash IS NULL;
ALTER TABLE ledger_transaction ALTER COLUMN request_hash SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ledger_transaction_tenant_source_unique
  ON ledger_transaction (tenant_id, source_kind, source_id);
CREATE UNIQUE INDEX IF NOT EXISTS ledger_transaction_tenant_identity_unique
  ON ledger_transaction (id, tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ledger_transaction_single_reversal_unique
  ON ledger_transaction (tenant_id, reversal_of) WHERE reversal_of IS NOT NULL;

ALTER TABLE ledger_transaction
  DROP CONSTRAINT IF EXISTS ledger_transaction_reversal_of_fk;
ALTER TABLE ledger_transaction
  ADD CONSTRAINT ledger_transaction_reversal_of_fk
  FOREIGN KEY (reversal_of, tenant_id)
  REFERENCES ledger_transaction(id, tenant_id);
ALTER TABLE ledger_transaction
  DROP CONSTRAINT IF EXISTS ledger_transaction_adjustment_approval_check;
ALTER TABLE ledger_transaction
  ADD CONSTRAINT ledger_transaction_adjustment_approval_check
  CHECK (source_kind <> 'adjustment'
         OR (reason IS NOT NULL AND length(trim(reason)) > 0
             AND approved_by IS NOT NULL AND length(trim(approved_by)) > 0))
  NOT VALID;

CREATE TABLE IF NOT EXISTS ledger_entry (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  transaction_id uuid NOT NULL,
  account_id uuid NOT NULL,
  direction text NOT NULL CHECK (direction IN ('debit','credit')),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  posted_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_entry_tenant_transaction_idx
  ON ledger_entry (tenant_id, transaction_id);
CREATE INDEX IF NOT EXISTS ledger_entry_tenant_account_idx
  ON ledger_entry (tenant_id, account_id);

-- Generated schemas have single-column foreign keys. These additional
-- composite keys make a cross-tenant account/transaction reference impossible.
DO $elmpay$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ledger_entry_transaction_tenant_fk'
       AND conrelid = 'ledger_entry'::regclass
  ) THEN
    ALTER TABLE ledger_entry
      ADD CONSTRAINT ledger_entry_transaction_tenant_fk
      FOREIGN KEY (transaction_id, tenant_id)
      REFERENCES ledger_transaction(id, tenant_id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'ledger_entry_account_tenant_currency_fk'
       AND conrelid = 'ledger_entry'::regclass
  ) THEN
    ALTER TABLE ledger_entry
      ADD CONSTRAINT ledger_entry_account_tenant_currency_fk
      FOREIGN KEY (account_id, tenant_id, currency)
      REFERENCES ledger_account(id, tenant_id, currency);
  END IF;
END;
$elmpay$;

CREATE OR REPLACE FUNCTION elmpay_immutable_ledger() RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
  RAISE EXCEPTION 'ledger history is append-only' USING ERRCODE = '55000';
END;
$elmpay$;

DROP TRIGGER IF EXISTS ledger_transaction_immutable ON ledger_transaction;
CREATE TRIGGER ledger_transaction_immutable
BEFORE UPDATE OR DELETE ON ledger_transaction
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_ledger();
DROP TRIGGER IF EXISTS ledger_entry_immutable ON ledger_entry;
CREATE TRIGGER ledger_entry_immutable
BEFORE UPDATE OR DELETE ON ledger_entry
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_ledger();

CREATE OR REPLACE FUNCTION elmpay_check_ledger_balance() RETURNS trigger LANGUAGE plpgsql AS $elmpay$
DECLARE
  bad_count bigint;
  entry_count bigint;
  target_transaction_id uuid;
  target_tenant_id uuid;
BEGIN
  IF TG_TABLE_NAME = 'ledger_transaction' THEN
    target_transaction_id := NEW.id;
    target_tenant_id := NEW.tenant_id;
  ELSE
    target_transaction_id := NEW.transaction_id;
    target_tenant_id := NEW.tenant_id;
  END IF;
  SELECT count(*) INTO entry_count
    FROM ledger_entry
   WHERE tenant_id = target_tenant_id AND transaction_id = target_transaction_id;
  SELECT count(*) INTO bad_count FROM (
    SELECT currency
      FROM ledger_entry
     WHERE tenant_id = target_tenant_id AND transaction_id = target_transaction_id
     GROUP BY currency
    HAVING sum(CASE direction WHEN 'debit' THEN amount_minor ELSE -amount_minor END) <> 0
  ) imbalance;
  IF entry_count < 2 OR bad_count <> 0 THEN
    RAISE EXCEPTION 'ledger transaction is empty or not balanced by currency' USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$elmpay$;

DROP TRIGGER IF EXISTS ledger_balance_deferred ON ledger_entry;
CREATE CONSTRAINT TRIGGER ledger_balance_deferred
AFTER INSERT ON ledger_entry DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION elmpay_check_ledger_balance();
DROP TRIGGER IF EXISTS ledger_transaction_balance_deferred ON ledger_transaction;
CREATE CONSTRAINT TRIGGER ledger_transaction_balance_deferred
AFTER INSERT ON ledger_transaction DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION elmpay_check_ledger_balance();

CREATE TABLE IF NOT EXISTS fee_record (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  source_type text NOT NULL,
  source_id text NOT NULL,
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  gross_minor bigint NOT NULL CHECK (gross_minor >= 0),
  fixed_minor bigint NOT NULL CHECK (fixed_minor >= 0),
  variable_minor bigint NOT NULL CHECK (variable_minor >= 0),
  tax_minor bigint NOT NULL CHECK (tax_minor >= 0),
  total_minor bigint NOT NULL CHECK (total_minor >= 0),
  rule_version text NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, source_type, source_id, rule_version)
);

CREATE TABLE IF NOT EXISTS fx_rate (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  source text NOT NULL,
  base_currency char(3) NOT NULL CHECK (base_currency ~ '^[A-Z]{3}$'),
  quote_currency char(3) NOT NULL CHECK (quote_currency ~ '^[A-Z]{3}$'),
  numerator bigint NOT NULL CHECK (numerator > 0),
  denominator bigint NOT NULL CHECK (denominator > 0),
  observed_at timestamptz NOT NULL,
  version text NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, source, base_currency, quote_currency, observed_at, version)
);

CREATE TABLE IF NOT EXISTS settlement_instruction (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  provider_batch_id text NOT NULL,
  currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  gross_minor bigint NOT NULL,
  fee_minor bigint NOT NULL,
  expected_bank_minor bigint NOT NULL,
  expected_arrival timestamptz NOT NULL,
  provider_status text NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (tenant_id, provider_batch_id)
);

DROP TRIGGER IF EXISTS fee_record_immutable ON fee_record;
CREATE TRIGGER fee_record_immutable BEFORE UPDATE OR DELETE ON fee_record
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_ledger();
DROP TRIGGER IF EXISTS fx_rate_immutable ON fx_rate;
CREATE TRIGGER fx_rate_immutable BEFORE UPDATE OR DELETE ON fx_rate
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_ledger();
DROP TRIGGER IF EXISTS settlement_instruction_immutable ON settlement_instruction;
CREATE TRIGGER settlement_instruction_immutable BEFORE UPDATE OR DELETE ON settlement_instruction
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_ledger();

-- FORCE prevents the table owner from bypassing tenant isolation. Missing
-- app.tenant_id yields NULL and therefore denies both reads and writes.
ALTER TABLE ledger_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_account FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_account_tenant_isolation ON ledger_account;
CREATE POLICY ledger_account_tenant_isolation ON ledger_account
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE ledger_transaction ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_transaction FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_transaction_tenant_isolation ON ledger_transaction;
CREATE POLICY ledger_transaction_tenant_isolation ON ledger_transaction
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE ledger_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_entry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_entry_tenant_isolation ON ledger_entry;
CREATE POLICY ledger_entry_tenant_isolation ON ledger_entry
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE fee_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE fee_record FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fee_record_tenant_isolation ON fee_record;
CREATE POLICY fee_record_tenant_isolation ON fee_record
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE fx_rate ENABLE ROW LEVEL SECURITY;
ALTER TABLE fx_rate FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fx_rate_tenant_isolation ON fx_rate;
CREATE POLICY fx_rate_tenant_isolation ON fx_rate
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE settlement_instruction ENABLE ROW LEVEL SECURITY;
ALTER TABLE settlement_instruction FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS settlement_instruction_tenant_isolation ON settlement_instruction;
CREATE POLICY settlement_instruction_tenant_isolation ON settlement_instruction
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON ledger_transaction, ledger_entry, fee_record, fx_rate, settlement_instruction FROM PUBLIC;
