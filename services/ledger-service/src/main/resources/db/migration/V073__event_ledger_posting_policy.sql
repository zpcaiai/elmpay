-- B72/B73 explicit event-to-ledger posting policy. V072 creates immutable ledger tables.
-- No policy or account mapping is seeded: each tenant/project/provider/currency binding requires
-- controlled onboarding. Missing or ambiguous policy therefore fails closed.

CREATE TABLE IF NOT EXISTS ledger_posting_policy (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    event_name text NOT NULL
        CHECK (event_name ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,7}$'),
    event_version integer NOT NULL CHECK (event_version > 0),
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    provider text NOT NULL
        CHECK (provider IN ('wechat','alipay','stripe','paypal','apple_pay')),
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    source_kind text NOT NULL CHECK (source_kind IN ('payment','refund')),
    debit_role text NOT NULL CHECK (debit_role ~ '^[a-z][a-z0-9_]{1,63}$'),
    credit_role text NOT NULL CHECK (credit_role ~ '^[a-z][a-z0-9_]{1,63}$'),
    description text NOT NULL CHECK (length(trim(description)) BETWEEN 1 AND 256),
    active boolean NOT NULL DEFAULT false,
    approved_by text NOT NULL CHECK (length(trim(approved_by)) BETWEEN 2 AND 128),
    approval_ticket_id text NOT NULL
        CHECK (length(trim(approval_ticket_id)) BETWEEN 2 AND 128),
    created_at timestamptz NOT NULL,
    deactivated_at timestamptz,
    CHECK (debit_role <> credit_role),
    CHECK ((active AND deactivated_at IS NULL) OR (NOT active)),
    UNIQUE (id, tenant_id, project_id),
    UNIQUE (tenant_id, project_id, event_name, event_version, currency, provider,
            policy_version)
);

CREATE UNIQUE INDEX IF NOT EXISTS ledger_posting_policy_one_active_unique
    ON ledger_posting_policy
       (tenant_id, project_id, event_name, event_version, currency, provider)
    WHERE active;

CREATE TABLE IF NOT EXISTS ledger_posting_account_mapping (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    account_role text NOT NULL CHECK (account_role ~ '^[a-z][a-z0-9_]{1,63}$'),
    account_id uuid NOT NULL,
    currency char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, policy_id, account_role),
    FOREIGN KEY (policy_id, tenant_id, project_id)
        REFERENCES ledger_posting_policy(id, tenant_id, project_id),
    FOREIGN KEY (account_id, tenant_id, currency)
        REFERENCES ledger_account(id, tenant_id, currency)
);

CREATE TABLE IF NOT EXISTS ledger_event_revision_guard (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    aggregate_type text NOT NULL CHECK (aggregate_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    aggregate_id uuid NOT NULL,
    last_revision bigint NOT NULL CHECK (last_revision > 0),
    last_event_id uuid NOT NULL,
    last_event_name text NOT NULL,
    last_envelope_sha256 char(64) NOT NULL
        CHECK (last_envelope_sha256 ~ '^[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, aggregate_type, aggregate_id)
);

CREATE OR REPLACE FUNCTION elmpay_protect_posting_policy()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ledger posting policy history is append-only' USING ERRCODE = '55000';
    END IF;
    IF OLD.active AND NOT NEW.active
       AND NEW.deactivated_at IS NOT NULL
       AND NEW.id = OLD.id
       AND NEW.tenant_id = OLD.tenant_id
       AND NEW.project_id = OLD.project_id
       AND NEW.event_name = OLD.event_name
       AND NEW.event_version = OLD.event_version
       AND NEW.currency = OLD.currency
       AND NEW.provider = OLD.provider
       AND NEW.policy_version = OLD.policy_version
       AND NEW.source_kind = OLD.source_kind
       AND NEW.debit_role = OLD.debit_role
       AND NEW.credit_role = OLD.credit_role
       AND NEW.description = OLD.description
       AND NEW.approved_by = OLD.approved_by
       AND NEW.approval_ticket_id = OLD.approval_ticket_id
       AND NEW.created_at = OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'ledger posting policy may only be deactivated' USING ERRCODE = '55000';
END;
$elmpay$;

DROP TRIGGER IF EXISTS ledger_posting_policy_guard ON ledger_posting_policy;
CREATE TRIGGER ledger_posting_policy_guard
BEFORE UPDATE OR DELETE ON ledger_posting_policy
FOR EACH ROW EXECUTE FUNCTION elmpay_protect_posting_policy();

DROP TRIGGER IF EXISTS ledger_posting_account_mapping_immutable
    ON ledger_posting_account_mapping;
CREATE TRIGGER ledger_posting_account_mapping_immutable
BEFORE UPDATE OR DELETE ON ledger_posting_account_mapping
FOR EACH ROW EXECUTE FUNCTION elmpay_immutable_ledger();

ALTER TABLE ledger_posting_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_posting_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_posting_policy_tenant_isolation ON ledger_posting_policy;
CREATE POLICY ledger_posting_policy_tenant_isolation ON ledger_posting_policy
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE ledger_posting_account_mapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_posting_account_mapping FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_posting_mapping_tenant_isolation
    ON ledger_posting_account_mapping;
CREATE POLICY ledger_posting_mapping_tenant_isolation ON ledger_posting_account_mapping
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE ledger_event_revision_guard ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_event_revision_guard FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_event_revision_tenant_isolation
    ON ledger_event_revision_guard;
CREATE POLICY ledger_event_revision_tenant_isolation ON ledger_event_revision_guard
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON ledger_posting_account_mapping,
    ledger_event_revision_guard FROM PUBLIC;
