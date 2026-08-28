PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenant_isolation_probe_run (
  run_id TEXT PRIMARY KEY,
  request_digest TEXT NOT NULL UNIQUE CHECK (length(request_digest) = 64),
  owner_tenant_id TEXT NOT NULL,
  attacker_tenant_id TEXT NOT NULL,
  canary_id TEXT NOT NULL,
  expected_digest TEXT NOT NULL CHECK (length(expected_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('RUNNING', 'PASSED', 'FAILED')),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  result_digest TEXT CHECK (result_digest IS NULL OR length(result_digest) = 64),
  CHECK (owner_tenant_id <> attacker_tenant_id)
);

CREATE TABLE IF NOT EXISTS tenant_isolation_probe_result (
  run_id TEXT NOT NULL REFERENCES tenant_isolation_probe_run(run_id),
  surface TEXT NOT NULL CHECK (surface IN ('database', 'cache', 'message', 'log', 'export')),
  status TEXT NOT NULL CHECK (status IN ('PASSED', 'FAILED')),
  owner_visible INTEGER NOT NULL CHECK (owner_visible IN (0, 1)),
  cross_tenant_denied INTEGER NOT NULL CHECK (cross_tenant_denied IN (0, 1)),
  response_digest TEXT NOT NULL CHECK (length(response_digest) = 64),
  reason_code TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (run_id, surface)
);

CREATE TRIGGER IF NOT EXISTS tenant_isolation_probe_run_no_update
BEFORE UPDATE ON tenant_isolation_probe_run
WHEN OLD.status <> 'RUNNING'
BEGIN
  SELECT RAISE(ABORT, 'completed isolation probe runs are immutable');
END;
CREATE TRIGGER IF NOT EXISTS tenant_isolation_probe_result_no_update
BEFORE UPDATE ON tenant_isolation_probe_result
BEGIN
  SELECT RAISE(ABORT, 'isolation probe results are immutable');
END;
