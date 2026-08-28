PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS brand_official_domain (
  tenant_id TEXT NOT NULL,
  domain_ascii TEXT NOT NULL,
  domain_skeleton TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, domain_ascii)
);

CREATE TABLE IF NOT EXISTS brand_observation (
  tenant_id TEXT NOT NULL,
  source TEXT NOT NULL,
  observation_id TEXT NOT NULL,
  candidate_domain_ascii TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  decision_digest TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'REVIEW', 'TAKEDOWN_CANDIDATE')),
  severity TEXT NOT NULL CHECK (severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  reasons_json TEXT NOT NULL,
  features_json TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, source, observation_id)
);

CREATE INDEX IF NOT EXISTS brand_observation_domain_idx
  ON brand_observation (tenant_id, candidate_domain_ascii, observed_at);

CREATE TABLE IF NOT EXISTS brand_takedown_case (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  candidate_domain_ascii TEXT NOT NULL,
  observation_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK (
    status IN ('OPEN', 'TRIAGED', 'EVIDENCE_PRESERVED', 'PROVIDER_SUBMITTED', 'RESOLVED', 'DISMISSED')
  ),
  severity TEXT NOT NULL CHECK (severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
  external_receipt TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id),
  UNIQUE (tenant_id, observation_digest)
);

CREATE TABLE IF NOT EXISTS brand_takedown_action (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  reviewer TEXT,
  reason TEXT NOT NULL,
  before_status TEXT NOT NULL,
  after_status TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  external_receipt TEXT,
  occurred_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id, action_id),
  FOREIGN KEY (tenant_id, case_id)
    REFERENCES brand_takedown_case (tenant_id, case_id)
);

CREATE TABLE IF NOT EXISTS abuse_counter (
  tenant_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  layer TEXT NOT NULL CHECK (layer IN ('CDN', 'WAF', 'API', 'IDENTITY')),
  dimension TEXT NOT NULL CHECK (dimension IN ('TENANT', 'ACCOUNT', 'DEVICE', 'IP')),
  subject_digest TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  used INTEGER NOT NULL CHECK (used >= 0),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (
    tenant_id, policy_version, layer, dimension, subject_digest, window_start
  )
);

CREATE TABLE IF NOT EXISTS browser_security_report (
  deployment_id TEXT NOT NULL,
  report_id TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('CSP', 'BROWSER_INTEGRITY')),
  policy_version TEXT NOT NULL,
  report_digest TEXT NOT NULL,
  report_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY (deployment_id, report_id)
);

CREATE INDEX IF NOT EXISTS browser_security_report_time_idx
  ON browser_security_report (deployment_id, occurred_at);

CREATE INDEX IF NOT EXISTS abuse_counter_expiry_idx ON abuse_counter (expires_at);

CREATE TABLE IF NOT EXISTS abuse_decision (
  tenant_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  layer TEXT NOT NULL CHECK (layer IN ('CDN', 'WAF', 'API', 'IDENTITY')),
  action TEXT NOT NULL CHECK (action IN ('ALLOW', 'CHALLENGE', 'BLOCK')),
  risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 10000),
  reasons_json TEXT NOT NULL,
  challenge_id TEXT,
  case_id TEXT,
  occurred_at TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS abuse_challenge (
  tenant_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  challenge_type TEXT NOT NULL CHECK (challenge_type IN ('BOT_PROOF', 'WEBAUTHN_STEP_UP')),
  binding_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'PASSED', 'EXPIRED', 'REVOKED')),
  expires_at TEXT NOT NULL,
  completed_at TEXT,
  PRIMARY KEY (tenant_id, challenge_id),
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES abuse_decision (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS abuse_security_case (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  case_type TEXT NOT NULL CHECK (case_type IN ('DDOS', 'BOT', 'CREDENTIAL_STUFFING', 'ATO')),
  status TEXT NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')),
  severity TEXT NOT NULL CHECK (severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
  subject_digest TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id)
);

CREATE TABLE IF NOT EXISTS abuse_case_event (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  reviewer TEXT,
  reason TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id, event_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES abuse_security_case (tenant_id, case_id)
);

CREATE TABLE IF NOT EXISTS abuse_session_revocation (
  tenant_id TEXT NOT NULL,
  session_digest TEXT NOT NULL,
  request_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  revoked_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, session_digest)
);

CREATE TRIGGER IF NOT EXISTS brand_observation_no_update
BEFORE UPDATE ON brand_observation
BEGIN
  SELECT RAISE(ABORT, 'brand observations are immutable');
END;

CREATE TRIGGER IF NOT EXISTS brand_observation_no_delete
BEFORE DELETE ON brand_observation
BEGIN
  SELECT RAISE(ABORT, 'brand observations are immutable');
END;

CREATE TRIGGER IF NOT EXISTS brand_action_no_update
BEFORE UPDATE ON brand_takedown_action
BEGIN
  SELECT RAISE(ABORT, 'brand takedown actions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS brand_action_no_delete
BEFORE DELETE ON brand_takedown_action
BEGIN
  SELECT RAISE(ABORT, 'brand takedown actions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS abuse_decision_no_update
BEFORE UPDATE ON abuse_decision
BEGIN
  SELECT RAISE(ABORT, 'abuse decisions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_security_report_no_update
BEFORE UPDATE ON browser_security_report
BEGIN
  SELECT RAISE(ABORT, 'browser security reports are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_security_report_no_delete
BEFORE DELETE ON browser_security_report
BEGIN
  SELECT RAISE(ABORT, 'browser security reports are immutable');
END;

CREATE TRIGGER IF NOT EXISTS abuse_decision_no_delete
BEFORE DELETE ON abuse_decision
BEGIN
  SELECT RAISE(ABORT, 'abuse decisions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS abuse_case_event_no_update
BEFORE UPDATE ON abuse_case_event
BEGIN
  SELECT RAISE(ABORT, 'abuse case events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS abuse_case_event_no_delete
BEFORE DELETE ON abuse_case_event
BEGIN
  SELECT RAISE(ABORT, 'abuse case events are immutable');
END;
