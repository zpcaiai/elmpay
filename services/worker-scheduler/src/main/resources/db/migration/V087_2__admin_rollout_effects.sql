-- Worker-owned durable internal rollout approval effect. This is not external release approval and does not
-- advance a rollout; a separately governed rollout controller owns stage transitions.

CREATE TABLE IF NOT EXISTS rollout_execution (
    rollout_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    release_binding_digest char(64) NOT NULL
        CHECK (release_binding_digest ~ '^[0-9a-f]{64}$'),
    target_digest char(64) NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
    provider_id text NOT NULL CHECK (provider_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    region text NOT NULL CHECK (region ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    artifact_digest char(64) NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
    previous_artifact_digest char(64) NOT NULL
        CHECK (previous_artifact_digest ~ '^[0-9a-f]{64}$'),
    stage_index integer NOT NULL CHECK (stage_index >= 0),
    stage_started_at timestamptz NOT NULL,
    stage_proposal_digest char(64) NOT NULL
        CHECK (stage_proposal_digest ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('RUNNING','STOPPED','ROLLED_BACK','COMPLETE')),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, rollout_id)
);

CREATE TABLE IF NOT EXISTS admin_rollout_stage_approval (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    approval_record_id uuid NOT NULL UNIQUE,
    command_id uuid NOT NULL UNIQUE,
    rollout_id uuid NOT NULL,
    stage_index integer NOT NULL CHECK (stage_index >= 0),
    stage_proposal_digest char(64) NOT NULL
        CHECK (stage_proposal_digest ~ '^[0-9a-f]{64}$'),
    policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    proposer_digest char(64) NOT NULL CHECK (proposer_digest ~ '^[0-9a-f]{64}$'),
    approver_digest char(64) NOT NULL CHECK (approver_digest ~ '^[0-9a-f]{64}$'),
    rollout_fencing_token bigint NOT NULL CHECK (rollout_fencing_token > 0),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, approval_record_id),
    UNIQUE (tenant_id, rollout_id, stage_index, stage_proposal_digest),
    FOREIGN KEY (tenant_id, rollout_id)
        REFERENCES rollout_execution (tenant_id, rollout_id),
    CHECK (proposer_digest <> approver_digest)
);

CREATE OR REPLACE FUNCTION elmpay_admin_rollout_approval_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $elmpay$
BEGIN
    RAISE EXCEPTION 'internal rollout approvals are append only' USING ERRCODE = '55000';
END;
$elmpay$;

DROP TRIGGER IF EXISTS admin_rollout_stage_approval_immutable
    ON admin_rollout_stage_approval;
CREATE TRIGGER admin_rollout_stage_approval_immutable
BEFORE UPDATE OR DELETE ON admin_rollout_stage_approval
FOR EACH ROW EXECUTE FUNCTION elmpay_admin_rollout_approval_immutable();

ALTER TABLE rollout_execution ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_execution FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_rollout_stage_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_rollout_stage_approval FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rollout_execution_tenant_policy ON rollout_execution;
CREATE POLICY rollout_execution_tenant_policy ON rollout_execution
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS admin_rollout_stage_approval_tenant_policy
    ON admin_rollout_stage_approval;
CREATE POLICY admin_rollout_stage_approval_tenant_policy
    ON admin_rollout_stage_approval
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON rollout_execution, admin_rollout_stage_approval FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION elmpay_admin_rollout_approval_immutable() FROM PUBLIC;

-- The worker identity is provisioned before migrations. It can consume only ROLLOUT commands;
-- PostgreSQL row binding and the Java consumer reject every other consumer_group.
GRANT SELECT, UPDATE ON admin_domain_command TO elmpay_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_domain_command_signal TO elmpay_worker;
GRANT SELECT, INSERT ON admin_action_effect_receipt TO elmpay_worker;
GRANT SELECT, UPDATE ON rollout_execution TO elmpay_worker;
GRANT SELECT, INSERT ON admin_rollout_stage_approval TO elmpay_worker;
GRANT SELECT, INSERT, UPDATE ON event_aggregate_revision TO elmpay_worker;
GRANT INSERT ON outbox_event TO elmpay_worker;
GRANT USAGE, SELECT ON SEQUENCE outbox_event_sequence_no_seq TO elmpay_worker;

-- Rollback is manual: stop the rollout owner and command consumer, preserve approval receipts,
-- reconcile UNKNOWN commands, then remove policies, trigger, function and tables.
