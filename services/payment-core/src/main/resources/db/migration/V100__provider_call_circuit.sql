CREATE TABLE provider_call_circuit (
    tenant_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{1,31}$'),
    state text NOT NULL CHECK (state IN ('HEALTHY','DEGRADED','OPEN','HALF_OPEN','UNKNOWN')),
    open_until timestamptz,
    half_open_successes integer NOT NULL DEFAULT 0 CHECK (half_open_successes >= 0),
    half_open_in_flight boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider_account_id, provider)
);

CREATE TABLE provider_call_outcome (
    outcome_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{1,31}$'),
    operation text NOT NULL CHECK (operation IN (
        'CREATE_PAYMENT','QUERY_PAYMENT','CAPTURE','CANCEL',
        'REFUND','QUERY_REFUND','VERIFY_WEBHOOK')),
    observed_at timestamptz NOT NULL,
    succeeded boolean NOT NULL,
    latency_ms integer NOT NULL CHECK (latency_ms >= 0),
    error_class text CHECK (error_class IS NULL OR error_class IN (
        'UNKNOWN_OUTCOME','CALL_REJECTED','RETRYABLE_PROVIDER_FAILURE','RUNTIME_FAILURE'))
);

CREATE INDEX provider_call_outcome_window
    ON provider_call_outcome(tenant_id, provider_account_id, provider, observed_at DESC);

ALTER TABLE provider_call_circuit ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_call_circuit FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_call_outcome ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_call_outcome FORCE ROW LEVEL SECURITY;

CREATE POLICY provider_call_circuit_tenant ON provider_call_circuit
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY provider_call_outcome_tenant ON provider_call_outcome
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
