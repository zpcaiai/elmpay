CREATE TABLE routing_policy_version (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    version text NOT NULL,
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    created_by text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, version),
    UNIQUE (tenant_id, project_id, content_digest)
);

CREATE TABLE routing_policy_rule (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    version text NOT NULL,
    provider_account_id uuid NOT NULL,
    priority integer NOT NULL CHECK (priority >= 0),
    min_amount_minor bigint NOT NULL CHECK (min_amount_minor >= 0),
    max_amount_minor bigint NOT NULL CHECK (max_amount_minor >= min_amount_minor),
    enabled boolean NOT NULL,
    PRIMARY KEY (tenant_id, project_id, version, provider_account_id),
    FOREIGN KEY (tenant_id, project_id, version)
        REFERENCES routing_policy_version(tenant_id, project_id, version),
    FOREIGN KEY (provider_account_id) REFERENCES provider_account(id)
);

CREATE TABLE routing_policy_approval (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    version text NOT NULL,
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    approver_id text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    approved_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id, version, approver_id),
    FOREIGN KEY (tenant_id, project_id, version)
        REFERENCES routing_policy_version(tenant_id, project_id, version)
);

CREATE TABLE routing_policy_assignment (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    stable_version text NOT NULL,
    candidate_version text,
    canary_basis_points integer NOT NULL CHECK (canary_basis_points BETWEEN 0 AND 2500),
    previous_stable_version text,
    previous_candidate_version text,
    previous_canary_basis_points integer NOT NULL DEFAULT 0
        CHECK (previous_canary_basis_points BETWEEN 0 AND 2500),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, project_id),
    FOREIGN KEY (tenant_id, project_id, stable_version)
        REFERENCES routing_policy_version(tenant_id, project_id, version),
    FOREIGN KEY (tenant_id, project_id, candidate_version)
        REFERENCES routing_policy_version(tenant_id, project_id, version),
    CHECK ((candidate_version IS NULL) = (canary_basis_points = 0)),
    CHECK (candidate_version IS NULL OR candidate_version <> stable_version)
);

CREATE TABLE routing_policy_change (
    change_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('PROPOSE','APPROVE','ACTIVATE','ROLLBACK')),
    stable_version text NOT NULL,
    candidate_version text,
    canary_basis_points integer NOT NULL CHECK (canary_basis_points BETWEEN 0 AND 2500),
    previous_stable_version text,
    previous_candidate_version text,
    previous_canary_basis_points integer NOT NULL CHECK (previous_canary_basis_points BETWEEN 0 AND 2500),
    actor_id text NOT NULL,
    reason text NOT NULL,
    ticket_id text NOT NULL,
    occurred_at timestamptz NOT NULL
);

CREATE TABLE routing_decision (
    decision_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    split_key_digest char(64) NOT NULL CHECK (split_key_digest ~ '^[0-9a-f]{64}$'),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    evaluated_routes_digest char(64) NOT NULL
        CHECK (evaluated_routes_digest ~ '^[0-9a-f]{64}$'),
    selected_version text NOT NULL,
    provider_account_id uuid NOT NULL,
    decided_at timestamptz NOT NULL,
    UNIQUE (tenant_id, project_id, split_key_digest),
    FOREIGN KEY (tenant_id, project_id, selected_version)
        REFERENCES routing_policy_version(tenant_id, project_id, version),
    FOREIGN KEY (provider_account_id) REFERENCES provider_account(id)
);

CREATE INDEX routing_policy_rule_lookup_idx
    ON routing_policy_rule (tenant_id, project_id, version, enabled,
                            min_amount_minor, max_amount_minor, priority);

CREATE OR REPLACE FUNCTION elmpay_reject_immutable_routing_fact_mutation()
RETURNS trigger LANGUAGE plpgsql AS $elmpay$
BEGIN
    RAISE EXCEPTION 'versioned routing facts are immutable';
END
$elmpay$;

CREATE TRIGGER routing_policy_version_no_mutation
BEFORE UPDATE OR DELETE ON routing_policy_version
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_immutable_routing_fact_mutation();
CREATE TRIGGER routing_policy_rule_no_mutation
BEFORE UPDATE OR DELETE ON routing_policy_rule
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_immutable_routing_fact_mutation();
CREATE TRIGGER routing_policy_approval_no_mutation
BEFORE UPDATE OR DELETE ON routing_policy_approval
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_immutable_routing_fact_mutation();
CREATE TRIGGER routing_policy_change_no_mutation
BEFORE UPDATE OR DELETE ON routing_policy_change
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_immutable_routing_fact_mutation();
CREATE TRIGGER routing_decision_no_mutation
BEFORE UPDATE OR DELETE ON routing_decision
FOR EACH ROW EXECUTE FUNCTION elmpay_reject_immutable_routing_fact_mutation();

ALTER TABLE routing_policy_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_policy_version FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_policy_version_tenant ON routing_policy_version
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE routing_policy_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_policy_rule FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_policy_rule_tenant ON routing_policy_rule
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE routing_policy_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_policy_approval FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_policy_approval_tenant ON routing_policy_approval
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE routing_policy_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_policy_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_policy_assignment_tenant ON routing_policy_assignment
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE routing_policy_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_policy_change FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_policy_change_tenant ON routing_policy_change
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE routing_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_decision FORCE ROW LEVEL SECURITY;
CREATE POLICY routing_decision_tenant ON routing_decision
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE, TRUNCATE ON routing_policy_version, routing_policy_rule,
    routing_policy_approval, routing_policy_change, routing_decision FROM PUBLIC;

-- Rollback is manual and destructive: drop decision/change/assignment/approval/rule/version.
