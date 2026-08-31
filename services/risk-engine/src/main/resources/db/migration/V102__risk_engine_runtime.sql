-- B80/B81/B82/B83/B87 deployable risk runtime. Additive only.

CREATE TABLE IF NOT EXISTS risk_runtime_nonce (
    nonce_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    nonce_digest char(64) NOT NULL UNIQUE CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
    caller_spiffe_digest char(64) NOT NULL CHECK (caller_spiffe_digest ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > issued_at),
    CHECK (consumed_at IS NULL OR consumed_at >= issued_at)
);
CREATE INDEX IF NOT EXISTS risk_runtime_nonce_lookup_idx
    ON risk_runtime_nonce (tenant_id, project_id, request_id, nonce_digest)
    WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS risk_runtime_rule_set (
    proposal_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    rule_set_version text NOT NULL CHECK (rule_set_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    rules_json jsonb NOT NULL CHECK (jsonb_typeof(rules_json) = 'array'
        AND jsonb_array_length(rules_json) BETWEEN 1 AND 256),
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('PENDING', 'APPROVED', 'ACTIVE', 'REJECTED', 'EXPIRED')),
    proposed_by_digest char(64) NOT NULL CHECK (proposed_by_digest ~ '^[0-9a-f]{64}$'),
    approved_by_digest char(64) CHECK (approved_by_digest ~ '^[0-9a-f]{64}$'),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    ticket_digest char(64) NOT NULL CHECK (ticket_digest ~ '^[0-9a-f]{64}$'),
    record_version bigint NOT NULL DEFAULT 1 CHECK (record_version > 0),
    proposed_at timestamptz NOT NULL,
    approval_expires_at timestamptz NOT NULL,
    approved_at timestamptz,
    activated_at timestamptz,
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, project_id, rule_set_version),
    CHECK (approval_expires_at > proposed_at AND expires_at > proposed_at),
    CHECK (approved_by_digest IS NULL OR approved_by_digest <> proposed_by_digest),
    CHECK ((state = 'PENDING' AND approved_by_digest IS NULL AND approved_at IS NULL)
        OR (state IN ('APPROVED', 'ACTIVE') AND approved_by_digest IS NOT NULL
            AND approved_at IS NOT NULL)
        OR state IN ('REJECTED', 'EXPIRED')),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS risk_runtime_one_active_rule_set
    ON risk_runtime_rule_set (tenant_id, project_id) WHERE state = 'ACTIVE';

CREATE TABLE IF NOT EXISTS risk_runtime_capability_health (
    capability text PRIMARY KEY CHECK (capability = 'risk_decision'),
    active_rule_set_digest char(64) NOT NULL CHECK (active_rule_set_digest ~ '^[0-9a-f]{64}$'),
    valid_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_runtime_signal_snapshot (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    request_id text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    signal_version text NOT NULL,
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    collected_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    values_json jsonb NOT NULL CHECK (jsonb_typeof(values_json) = 'object'),
    source_status text NOT NULL CHECK (source_status IN ('AVAILABLE', 'UNAVAILABLE')),
    PRIMARY KEY (tenant_id, project_id, request_id),
    CHECK (expires_at > collected_at)
);

CREATE TABLE IF NOT EXISTS risk_runtime_model_result (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    request_id text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    signal_digest char(64) NOT NULL CHECK (signal_digest ~ '^[0-9a-f]{64}$'),
    model_version text NOT NULL,
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    score_decimal numeric(38,18) NOT NULL CHECK (score_decimal >= 0 AND score_decimal <= 1),
    explanation_code text NOT NULL CHECK (explanation_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    source_status text NOT NULL CHECK (source_status IN ('AVAILABLE', 'UNAVAILABLE')),
    evaluated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, request_id)
);

CREATE TABLE IF NOT EXISTS risk_runtime_decision (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    request_id text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    decision_id char(64) NOT NULL CHECK (decision_id ~ '^[0-9a-f]{64}$'),
    operation text NOT NULL CHECK (operation IN ('PAYMENT_CREATE', 'PAYMENT_CONFIRM',
        'PAYMENT_CAPTURE', 'REFUND_REQUEST', 'CREDENTIAL_CHANGE', 'PAYMENT_METHOD_ADD',
        'PRIVILEGE_ELEVATION')),
    subject_digest char(64) NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
    action text NOT NULL CHECK (action IN ('APPROVE', 'REVIEW', 'BLOCK')),
    reason_codes jsonb NOT NULL CHECK (jsonb_typeof(reason_codes) = 'array'
        AND jsonb_array_length(reason_codes) BETWEEN 1 AND 64),
    rule_set_version text NOT NULL,
    rule_set_digest char(64) NOT NULL CHECK (rule_set_digest ~ '^[0-9a-f]{64}$'),
    signal_version text NOT NULL,
    signal_digest char(64) NOT NULL CHECK (signal_digest ~ '^[0-9a-f]{64}$'),
    model_version text NOT NULL,
    model_digest char(64) NOT NULL CHECK (model_digest ~ '^[0-9a-f]{64}$'),
    degraded boolean NOT NULL,
    decided_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, request_id),
    UNIQUE (tenant_id, decision_id),
    CHECK (action <> 'APPROVE' OR degraded = false)
);

CREATE TABLE IF NOT EXISTS risk_runtime_operation_request (
    operation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('LIST_ADD', 'LIST_REMOVE', 'CASE_CLOSE')),
    subject_digest char(64) NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
    proposal_digest char(64) NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    proposed_by_digest char(64) NOT NULL CHECK (proposed_by_digest ~ '^[0-9a-f]{64}$'),
    approved_by_digest char(64) CHECK (approved_by_digest ~ '^[0-9a-f]{64}$'),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    ticket_digest char(64) NOT NULL CHECK (ticket_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('PENDING', 'APPLIED', 'REJECTED', 'EXPIRED')),
    record_version bigint NOT NULL DEFAULT 1 CHECK (record_version > 0),
    proposed_at timestamptz NOT NULL,
    approval_expires_at timestamptz NOT NULL,
    applied_at timestamptz,
    CHECK (approval_expires_at > proposed_at),
    CHECK (approved_by_digest IS NULL OR approved_by_digest <> proposed_by_digest),
    CHECK ((state = 'PENDING' AND approved_by_digest IS NULL AND applied_at IS NULL)
        OR (state = 'APPLIED' AND approved_by_digest IS NOT NULL AND applied_at IS NOT NULL)
        OR state IN ('REJECTED', 'EXPIRED'))
);

CREATE TABLE IF NOT EXISTS risk_runtime_list_entry (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    subject_digest char(64) NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
    source_operation_id uuid NOT NULL UNIQUE REFERENCES risk_runtime_operation_request(operation_id),
    active boolean NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, subject_digest)
);

CREATE TABLE IF NOT EXISTS risk_runtime_case_resolution (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    case_digest char(64) NOT NULL CHECK (case_digest ~ '^[0-9a-f]{64}$'),
    source_operation_id uuid NOT NULL UNIQUE REFERENCES risk_runtime_operation_request(operation_id),
    closed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, case_digest)
);

CREATE TABLE IF NOT EXISTS risk_runtime_audit (
    sequence_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    aggregate_type text NOT NULL CHECK (aggregate_type IN ('RULE_SET', 'OPERATION')),
    aggregate_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    actor_digest char(64) NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL
);

CREATE OR REPLACE FUNCTION risk_runtime_forbid_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'risk runtime immutable record cannot be changed';
END $$;

CREATE OR REPLACE FUNCTION risk_runtime_protect_rule_set() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.proposal_id <> OLD.proposal_id OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.project_id <> OLD.project_id OR NEW.rule_set_version <> OLD.rule_set_version
       OR NEW.rules_json <> OLD.rules_json OR NEW.content_digest <> OLD.content_digest
       OR NEW.policy_digest <> OLD.policy_digest OR NEW.proposed_by_digest <> OLD.proposed_by_digest
       OR NEW.reason_code <> OLD.reason_code OR NEW.ticket_digest <> OLD.ticket_digest
       OR NEW.proposed_at <> OLD.proposed_at OR NEW.approval_expires_at <> OLD.approval_expires_at
       OR NEW.expires_at <> OLD.expires_at OR NEW.record_version <> OLD.record_version + 1 THEN
        RAISE EXCEPTION 'immutable rule-set proposal content or version changed';
    END IF;
    IF NOT ((OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'REJECTED', 'EXPIRED'))
         OR (OLD.state = 'APPROVED' AND NEW.state IN ('ACTIVE', 'REJECTED', 'EXPIRED'))
         OR (OLD.state = 'ACTIVE' AND NEW.state = 'EXPIRED')) THEN
        RAISE EXCEPTION 'invalid rule-set state transition';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION risk_runtime_protect_operation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.operation_id <> OLD.operation_id OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.project_id <> OLD.project_id OR NEW.kind <> OLD.kind
       OR NEW.subject_digest <> OLD.subject_digest OR NEW.proposal_digest <> OLD.proposal_digest
       OR NEW.policy_digest <> OLD.policy_digest OR NEW.proposed_by_digest <> OLD.proposed_by_digest
       OR NEW.reason_code <> OLD.reason_code OR NEW.ticket_digest <> OLD.ticket_digest
       OR NEW.proposed_at <> OLD.proposed_at OR NEW.approval_expires_at <> OLD.approval_expires_at
       OR NEW.record_version <> OLD.record_version + 1 THEN
        RAISE EXCEPTION 'immutable operation proposal content or version changed';
    END IF;
    IF OLD.state <> 'PENDING' OR NEW.state NOT IN ('APPLIED', 'REJECTED', 'EXPIRED') THEN
        RAISE EXCEPTION 'invalid operation state transition';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION risk_runtime_protect_nonce() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.nonce_id <> OLD.nonce_id OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.project_id <> OLD.project_id OR NEW.request_id <> OLD.request_id
       OR NEW.request_digest <> OLD.request_digest OR NEW.nonce_digest <> OLD.nonce_digest
       OR NEW.caller_spiffe_digest <> OLD.caller_spiffe_digest
       OR NEW.issued_at <> OLD.issued_at OR NEW.expires_at <> OLD.expires_at
       OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
        RAISE EXCEPTION 'nonce binding is immutable and consumption is one-way';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION risk_runtime_validate_list_effect() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$ BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'risk list effect identity is immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND
       (NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id
        OR NEW.subject_digest <> OLD.subject_digest OR NEW.changed_at <= OLD.changed_at) THEN
        RAISE EXCEPTION 'risk list effect identity is immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM risk_runtime_operation_request operation
         WHERE operation.operation_id = NEW.source_operation_id
           AND operation.tenant_id = NEW.tenant_id
           AND operation.project_id = NEW.project_id
           AND operation.subject_digest = NEW.subject_digest
           AND operation.state = 'APPLIED'
           AND ((operation.kind = 'LIST_ADD' AND NEW.active)
             OR (operation.kind = 'LIST_REMOVE' AND NOT NEW.active))
    ) THEN
        RAISE EXCEPTION 'risk list effect is not bound to an applied operation';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION risk_runtime_validate_case_effect() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$ BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'risk case resolution is immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM risk_runtime_operation_request operation
         WHERE operation.operation_id = NEW.source_operation_id
           AND operation.tenant_id = NEW.tenant_id
           AND operation.project_id = NEW.project_id
           AND operation.subject_digest = NEW.case_digest
           AND operation.kind = 'CASE_CLOSE' AND operation.state = 'APPLIED'
    ) THEN
        RAISE EXCEPTION 'risk case effect is not bound to an applied operation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS risk_runtime_signal_immutable ON risk_runtime_signal_snapshot;
CREATE TRIGGER risk_runtime_signal_immutable BEFORE UPDATE OR DELETE
    ON risk_runtime_signal_snapshot FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_model_immutable ON risk_runtime_model_result;
CREATE TRIGGER risk_runtime_model_immutable BEFORE UPDATE OR DELETE
    ON risk_runtime_model_result FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_decision_immutable ON risk_runtime_decision;
CREATE TRIGGER risk_runtime_decision_immutable BEFORE UPDATE OR DELETE
    ON risk_runtime_decision FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_audit_immutable ON risk_runtime_audit;
CREATE TRIGGER risk_runtime_audit_immutable BEFORE UPDATE OR DELETE
    ON risk_runtime_audit FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_rule_set_protected ON risk_runtime_rule_set;
CREATE TRIGGER risk_runtime_rule_set_protected BEFORE UPDATE
    ON risk_runtime_rule_set FOR EACH ROW EXECUTE FUNCTION risk_runtime_protect_rule_set();
DROP TRIGGER IF EXISTS risk_runtime_rule_set_no_delete ON risk_runtime_rule_set;
CREATE TRIGGER risk_runtime_rule_set_no_delete BEFORE DELETE
    ON risk_runtime_rule_set FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_operation_protected ON risk_runtime_operation_request;
CREATE TRIGGER risk_runtime_operation_protected BEFORE UPDATE
    ON risk_runtime_operation_request FOR EACH ROW EXECUTE FUNCTION risk_runtime_protect_operation();
DROP TRIGGER IF EXISTS risk_runtime_operation_no_delete ON risk_runtime_operation_request;
CREATE TRIGGER risk_runtime_operation_no_delete BEFORE DELETE
    ON risk_runtime_operation_request FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_nonce_protected ON risk_runtime_nonce;
CREATE TRIGGER risk_runtime_nonce_protected BEFORE UPDATE
    ON risk_runtime_nonce FOR EACH ROW EXECUTE FUNCTION risk_runtime_protect_nonce();
DROP TRIGGER IF EXISTS risk_runtime_nonce_no_delete ON risk_runtime_nonce;
CREATE TRIGGER risk_runtime_nonce_no_delete BEFORE DELETE
    ON risk_runtime_nonce FOR EACH ROW EXECUTE FUNCTION risk_runtime_forbid_change();
DROP TRIGGER IF EXISTS risk_runtime_list_effect_guard ON risk_runtime_list_entry;
CREATE TRIGGER risk_runtime_list_effect_guard BEFORE INSERT OR UPDATE OR DELETE
    ON risk_runtime_list_entry FOR EACH ROW EXECUTE FUNCTION risk_runtime_validate_list_effect();
DROP TRIGGER IF EXISTS risk_runtime_case_effect_guard ON risk_runtime_case_resolution;
CREATE TRIGGER risk_runtime_case_effect_guard BEFORE INSERT OR UPDATE OR DELETE
    ON risk_runtime_case_resolution FOR EACH ROW EXECUTE FUNCTION risk_runtime_validate_case_effect();

DO $$ DECLARE table_name text; BEGIN
    FOREACH table_name IN ARRAY ARRAY[
      'risk_runtime_nonce', 'risk_runtime_rule_set', 'risk_runtime_signal_snapshot',
      'risk_runtime_model_result', 'risk_runtime_decision', 'risk_runtime_operation_request',
      'risk_runtime_list_entry', 'risk_runtime_case_resolution', 'risk_runtime_audit'
    ] LOOP
      EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
      EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
      EXECUTE format('DROP POLICY IF EXISTS %I ON %I', table_name || '_tenant_policy', table_name);
      EXECUTE format('CREATE POLICY %I ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true)::uuid)', table_name || '_tenant_policy', table_name);
    END LOOP;
END $$;

REVOKE UPDATE, DELETE ON risk_runtime_signal_snapshot, risk_runtime_model_result,
    risk_runtime_decision, risk_runtime_audit FROM PUBLIC;
REVOKE DELETE ON risk_runtime_rule_set, risk_runtime_operation_request FROM PUBLIC;
REVOKE DELETE ON risk_runtime_nonce FROM PUBLIC;
REVOKE DELETE ON risk_runtime_capability_health FROM PUBLIC;

-- The runtime identity is provisioned before migrations. Grant only the statements exercised by
-- the decision/control paths and the risk-owned admin consumer; no evidence table is deletable.
GRANT SELECT, INSERT, UPDATE ON risk_runtime_nonce, risk_runtime_rule_set,
    risk_runtime_capability_health, risk_runtime_operation_request,
    risk_runtime_list_entry TO elmpay_risk_engine;
GRANT SELECT, INSERT ON risk_runtime_signal_snapshot, risk_runtime_model_result,
    risk_runtime_decision, risk_runtime_case_resolution, risk_runtime_audit
    TO elmpay_risk_engine;
GRANT SELECT, INSERT, UPDATE ON event_aggregate_revision TO elmpay_risk_engine;
GRANT INSERT ON outbox_event TO elmpay_risk_engine;
GRANT SELECT, UPDATE ON admin_domain_command TO elmpay_risk_engine;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_domain_command_signal TO elmpay_risk_engine;
GRANT SELECT, INSERT ON admin_action_effect_receipt TO elmpay_risk_engine;
GRANT USAGE, SELECT ON SEQUENCE risk_runtime_audit_sequence_no_seq,
    outbox_event_sequence_no_seq TO elmpay_risk_engine;

-- Reversible rollback intentionally preserves evidence unless explicitly exported and approved.
