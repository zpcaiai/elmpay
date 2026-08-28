CREATE TABLE webhook_endpoint (
    tenant_id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    endpoint_id VARCHAR(64) NOT NULL,
    endpoint_uri TEXT NOT NULL,
    approved_host VARCHAR(253) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'PAUSED', 'REVOKED')),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 20),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id),
    CHECK (endpoint_uri ~ '^https://')
);

CREATE TABLE webhook_signing_key (
    tenant_id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    secret_ref VARCHAR(320) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'OVERLAP', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, key_id),
    CHECK (valid_until > valid_from),
    CHECK (secret_ref ~ '^(kms|hsm|vault)://')
);

CREATE TABLE webhook_delivery_outbox (
    delivery_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    endpoint_id VARCHAR(64) NOT NULL,
    event_id VARCHAR(160) NOT NULL,
    event_type VARCHAR(160) NOT NULL,
    payload BYTEA NOT NULL,
    state VARCHAR(16) NOT NULL CHECK (state IN ('PENDING', 'IN_FLIGHT', 'RETRY', 'DELIVERED', 'DEAD')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ,
    lease_owner VARCHAR(64),
    fencing_token BIGINT NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    last_status_code INTEGER,
    last_error_code VARCHAR(80),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, endpoint_id, event_id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES webhook_endpoint (tenant_id, endpoint_id),
    CHECK ((state = 'IN_FLIGHT') = (lease_until IS NOT NULL AND lease_owner IS NOT NULL))
);

CREATE INDEX webhook_delivery_due_idx
    ON webhook_delivery_outbox (tenant_id, next_attempt_at, delivery_id)
    WHERE state IN ('PENDING', 'RETRY', 'IN_FLIGHT');

CREATE TABLE webhook_delivery_dead_letter (
    delivery_id BIGINT NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    project_id VARCHAR(64) NOT NULL,
    endpoint_id VARCHAR(64) NOT NULL,
    event_id VARCHAR(160) NOT NULL,
    event_type VARCHAR(160) NOT NULL,
    payload BYTEA NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
    final_status_code INTEGER NOT NULL,
    final_error_code VARCHAR(80) NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL,
    replayed_at TIMESTAMPTZ,
    replayed_by VARCHAR(64),
    replay_ticket_id VARCHAR(160),
    PRIMARY KEY (tenant_id, delivery_id)
);

CREATE TABLE webhook_delivery_admin_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_id VARCHAR(160) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    approver_id VARCHAR(64) NOT NULL,
    reason VARCHAR(160) NOT NULL,
    ticket_id VARCHAR(160) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    CHECK (actor_id <> approver_id)
);

ALTER TABLE webhook_endpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoint_tenant_policy ON webhook_endpoint
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE webhook_signing_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_signing_key FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_signing_key_tenant_policy ON webhook_signing_key
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE webhook_delivery_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_delivery_outbox_tenant_policy ON webhook_delivery_outbox
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE webhook_delivery_dead_letter ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_dead_letter FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_delivery_dead_letter_tenant_policy ON webhook_delivery_dead_letter
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE webhook_delivery_admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_admin_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_delivery_admin_audit_tenant_policy ON webhook_delivery_admin_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Rollback order: admin_audit, dead_letter, outbox, signing_key, endpoint.
