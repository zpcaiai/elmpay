PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS attestation_nonce (
  issuer_key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
  accepted_at TEXT NOT NULL,
  PRIMARY KEY (issuer_key_id, nonce)
);

CREATE TABLE IF NOT EXISTS uat_run (
  run_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  suite_id TEXT NOT NULL,
  suite_version TEXT NOT NULL,
  release_binding_digest TEXT NOT NULL CHECK(length(release_binding_digest)=64),
  suite_digest TEXT NOT NULL CHECK(length(suite_digest)=64),
  status TEXT NOT NULL CHECK(status IN ('RUNNING','PASSED','FAILED')),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest)=64),
  candidate_bundle_json TEXT,
  UNIQUE (tenant_id, suite_id, suite_version, release_binding_digest)
);
CREATE TABLE IF NOT EXISTS uat_step_result (
  run_id TEXT NOT NULL REFERENCES uat_run(run_id),
  scenario_id TEXT NOT NULL,
  step_index INTEGER NOT NULL CHECK(step_index >= 0),
  action TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PASSED','FAILED')),
  input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
  output_digest TEXT NOT NULL CHECK(length(output_digest)=64),
  detail TEXT NOT NULL,
  PRIMARY KEY (run_id, scenario_id, step_index)
);

CREATE TABLE IF NOT EXISTS migration_project (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  source_system TEXT NOT NULL,
  canonical_version TEXT NOT NULL,
  mapping_digest TEXT NOT NULL CHECK(length(mapping_digest)=64),
  credential_ref TEXT NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('REGISTERED','IMPORT','DUAL_WRITE','SHADOW','CUTOVER','ROLLED_BACK','COMPLETE')),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id)
);
CREATE TABLE IF NOT EXISTS migration_checkpoint (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  stream TEXT NOT NULL,
  position INTEGER NOT NULL CHECK(position >= 0),
  record_digest TEXT NOT NULL CHECK(length(record_digest)=64),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, stream),
  FOREIGN KEY (tenant_id, project_id) REFERENCES migration_project(tenant_id, project_id)
);
CREATE TABLE IF NOT EXISTS migration_fact (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  source_record_id TEXT NOT NULL,
  canonical_version TEXT NOT NULL,
  fact_digest TEXT NOT NULL CHECK(length(fact_digest)=64),
  canonical_json TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, source_record_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES migration_project(tenant_id, project_id)
);
CREATE TABLE IF NOT EXISTS migration_webhook_inbox (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  delivery_id TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
  processed_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, delivery_id)
);
CREATE TABLE IF NOT EXISTS migration_audit (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  action TEXT NOT NULL,
  object_digest TEXT NOT NULL CHECK(length(object_digest)=64),
  occurred_at TEXT NOT NULL,
  audit_digest TEXT NOT NULL UNIQUE CHECK(length(audit_digest)=64)
);
CREATE TABLE IF NOT EXISTS shadow_run (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  canonical_version TEXT NOT NULL,
  dataset_digest TEXT NOT NULL CHECK(length(dataset_digest)=64),
  result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest)=64),
  sample_count INTEGER NOT NULL DEFAULT 0,
  mismatch_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('RUNNING','PASSED','FAILED')),
  created_at TEXT NOT NULL,
  finished_at TEXT,
  PRIMARY KEY (tenant_id, project_id, run_id)
);
CREATE TABLE IF NOT EXISTS shadow_result (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  baseline_digest TEXT NOT NULL CHECK(length(baseline_digest)=64),
  candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
  diff_digest TEXT NOT NULL CHECK(length(diff_digest)=64),
  matched INTEGER NOT NULL CHECK(matched IN (0,1)),
  redacted_diff_json TEXT NOT NULL,
  PRIMARY KEY (tenant_id, project_id, run_id, request_id),
  FOREIGN KEY (tenant_id, project_id, run_id) REFERENCES shadow_run(tenant_id, project_id, run_id)
);

CREATE TABLE IF NOT EXISTS onboarding_case (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  merchant_account_id TEXT NOT NULL,
  requester TEXT NOT NULL,
  configuration_version TEXT NOT NULL,
  configuration_digest TEXT,
  state TEXT NOT NULL CHECK(state IN ('OPEN','READY_FOR_APPROVAL','READY_FOR_EXTERNAL_ACTIVATION','ACTIVE','SUSPENDED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS onboarding_control (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  control_name TEXT NOT NULL,
  evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),
  details_json TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id, control_name),
  FOREIGN KEY (tenant_id, case_id) REFERENCES onboarding_case(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS onboarding_approval (
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  approver TEXT NOT NULL,
  configuration_digest TEXT NOT NULL CHECK(length(configuration_digest)=64),
  approved_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, case_id, approver),
  FOREIGN KEY (tenant_id, case_id) REFERENCES onboarding_case(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS onboarding_audit (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  action TEXT NOT NULL,
  digest TEXT NOT NULL CHECK(length(digest)=64),
  occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS external_control_operation (
  tenant_id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  status TEXT NOT NULL CHECK(status IN ('IN_FLIGHT','UNKNOWN','SUCCEEDED')),
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  lease_owner TEXT NOT NULL,
  lease_until TEXT NOT NULL,
  result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest)=64),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, operation_type, operation_id)
);

CREATE TABLE IF NOT EXISTS release_decision (
  decision_id TEXT PRIMARY KEY,
  release_binding_digest TEXT NOT NULL CHECK(length(release_binding_digest)=64),
  target_digest TEXT NOT NULL CHECK(length(target_digest)=64),
  decision TEXT NOT NULL CHECK(decision IN ('GO','NO_GO')),
  gate_digest TEXT NOT NULL CHECK(length(gate_digest)=64),
  signed_record_json TEXT NOT NULL,
  decided_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS release_decision_material (
  decision_id TEXT PRIMARY KEY REFERENCES release_decision(decision_id),
  artifact_digest TEXT NOT NULL CHECK(length(artifact_digest)=64),
  release_manifest_json TEXT NOT NULL,
  external_evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS release_decision_gate_input (
  decision_id TEXT PRIMARY KEY REFERENCES release_decision(decision_id),
  gate_inputs_digest TEXT NOT NULL CHECK(length(gate_inputs_digest)=64),
  gate_inputs_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rollout_execution (
  rollout_id TEXT PRIMARY KEY,
  release_binding_digest TEXT NOT NULL CHECK(length(release_binding_digest)=64),
  target_digest TEXT NOT NULL CHECK(length(target_digest)=64),
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  region TEXT NOT NULL,
  artifact_digest TEXT NOT NULL CHECK(length(artifact_digest)=64),
  previous_artifact_digest TEXT NOT NULL CHECK(length(previous_artifact_digest)=64),
  stage_index INTEGER NOT NULL DEFAULT 0,
  stage_started_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('RUNNING','STOPPED','ROLLBACK_IN_FLIGHT','ROLLED_BACK','COMPLETE','UNKNOWN')),
  fence_token INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rollout_policy_binding (
  rollout_id TEXT PRIMARY KEY REFERENCES rollout_execution(rollout_id),
  decision_id TEXT NOT NULL REFERENCES release_decision(decision_id),
  control_policy_digest TEXT NOT NULL CHECK(length(control_policy_digest)=64),
  rollout_policy_digest TEXT NOT NULL CHECK(length(rollout_policy_digest)=64),
  control_policy_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rollout_observation (
  rollout_id TEXT NOT NULL REFERENCES rollout_execution(rollout_id),
  observation_id TEXT NOT NULL,
  stage_name TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  metrics_digest TEXT NOT NULL CHECK(length(metrics_digest)=64),
  signed_record_json TEXT NOT NULL,
  decision TEXT NOT NULL CHECK(decision IN ('PASS','STOP','ROLLBACK','UNKNOWN')),
  PRIMARY KEY (rollout_id, observation_id)
);
CREATE TABLE IF NOT EXISTS rollout_rollback_operation (
  operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=64),
  rollout_id TEXT NOT NULL UNIQUE REFERENCES rollout_execution(rollout_id),
  tenant_id TEXT NOT NULL,
  release_binding_digest TEXT NOT NULL CHECK(length(release_binding_digest)=64),
  target_digest TEXT NOT NULL CHECK(length(target_digest)=64),
  artifact_digest TEXT NOT NULL CHECK(length(artifact_digest)=64),
  previous_artifact_digest TEXT NOT NULL CHECK(length(previous_artifact_digest)=64),
  observation_id TEXT NOT NULL,
  stage_name TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  metrics_digest TEXT NOT NULL CHECK(length(metrics_digest)=64),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key)=64),
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  status TEXT NOT NULL CHECK(status IN ('IN_FLIGHT','UNKNOWN','SUCCEEDED')),
  lease_owner TEXT NOT NULL,
  lease_until TEXT NOT NULL,
  signed_record_json TEXT NOT NULL,
  receipt_digest TEXT CHECK(receipt_digest IS NULL OR length(receipt_digest)=64),
  receipt_json TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_lease (
  job_key TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  fence_token INTEGER NOT NULL CHECK(fence_token > 0),
  lease_until TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reconciliation_window (
  tenant_id TEXT NOT NULL,
  window_id TEXT NOT NULL,
  window_kind TEXT NOT NULL CHECK(window_kind IN ('DAILY','WEEKLY','MONTHLY')),
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  currency TEXT NOT NULL CHECK(length(currency)=3),
  transaction_total_minor INTEGER NOT NULL,
  provider_total_minor INTEGER NOT NULL,
  bank_total_minor INTEGER NOT NULL,
  open_delta_minor INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('OPEN','CLOSED','BLOCKED')),
  fence_token INTEGER NOT NULL,
  digest TEXT NOT NULL CHECK(length(digest)=64),
  PRIMARY KEY (tenant_id, window_id)
);
CREATE TABLE IF NOT EXISTS reconciliation_source_receipt (
  tenant_id TEXT NOT NULL,
  window_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('transaction','provider','bank')),
  signer_identity TEXT NOT NULL,
  total_minor INTEGER NOT NULL CHECK(total_minor >= 0),
  record_count INTEGER NOT NULL CHECK(record_count >= 0),
  source_snapshot_digest TEXT NOT NULL CHECK(length(source_snapshot_digest)=64),
  receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64),
  receipt_json TEXT NOT NULL,
  PRIMARY KEY (tenant_id, window_id, source),
  FOREIGN KEY (tenant_id, window_id) REFERENCES reconciliation_window(tenant_id, window_id)
);

CREATE TABLE IF NOT EXISTS pricing_version (
  pricing_version_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  currency TEXT NOT NULL,
  effective_at TEXT NOT NULL,
  policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
  policy_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, effective_at)
);
CREATE TABLE IF NOT EXISTS usage_event (
  tenant_id TEXT NOT NULL,
  meter TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  pricing_version_id TEXT NOT NULL REFERENCES pricing_version(pricing_version_id),
  occurred_at TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
  PRIMARY KEY (tenant_id, meter, dedupe_key)
);
CREATE TABLE IF NOT EXISTS commercial_invoice (
  invoice_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  pricing_version_id TEXT NOT NULL REFERENCES pricing_version(pricing_version_id),
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  currency TEXT NOT NULL,
  subtotal_minor INTEGER NOT NULL CHECK(subtotal_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('ISSUED','VOID')),
  invoice_digest TEXT NOT NULL CHECK(length(invoice_digest)=64),
  issued_at TEXT NOT NULL,
  UNIQUE (tenant_id, period_start, period_end)
);
CREATE TABLE IF NOT EXISTS commercial_invoice_line (
  invoice_id TEXT NOT NULL REFERENCES commercial_invoice(invoice_id),
  meter TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity >= 0),
  unit_price_minor INTEGER NOT NULL CHECK(unit_price_minor >= 0),
  total_minor INTEGER NOT NULL CHECK(total_minor >= 0),
  PRIMARY KEY (invoice_id, meter)
);
CREATE TABLE IF NOT EXISTS commercial_invoice_priced_line (
  invoice_id TEXT NOT NULL REFERENCES commercial_invoice(invoice_id),
  pricing_version_id TEXT NOT NULL REFERENCES pricing_version(pricing_version_id),
  meter TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity >= 0),
  unit_price_minor INTEGER NOT NULL CHECK(unit_price_minor >= 0),
  total_minor INTEGER NOT NULL CHECK(total_minor >= 0),
  PRIMARY KEY (invoice_id, pricing_version_id, meter)
);
CREATE TABLE IF NOT EXISTS credit_request (
  request_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL REFERENCES commercial_invoice(invoice_id),
  requester TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REJECTED')),
  approver TEXT,
  requested_at TEXT NOT NULL,
  decided_at TEXT
);
CREATE TABLE IF NOT EXISTS credit_memo (
  memo_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES credit_request(request_id),
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  issued_at TEXT NOT NULL,
  memo_digest TEXT NOT NULL CHECK(length(memo_digest)=64)
);
CREATE TABLE IF NOT EXISTS support_sla_policy (
  tenant_id TEXT NOT NULL,
  version TEXT NOT NULL,
  effective_at TEXT NOT NULL,
  response_minutes INTEGER NOT NULL CHECK(response_minutes > 0),
  service_credit_basis_points INTEGER NOT NULL CHECK(service_credit_basis_points BETWEEN 0 AND 10000),
  policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
  PRIMARY KEY (tenant_id, version)
);
CREATE TABLE IF NOT EXISTS support_ticket (
  ticket_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('SEV1','SEV2','SEV3','SEV4')),
  policy_version TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  response_due_at TEXT NOT NULL,
  first_response_at TEXT,
  responder TEXT,
  status TEXT NOT NULL CHECK(status IN ('OPEN','RESPONDED','CLOSED')),
  sla_breached INTEGER NOT NULL DEFAULT 0 CHECK(sla_breached IN (0,1)),
  ticket_digest TEXT NOT NULL CHECK(length(ticket_digest)=64),
  FOREIGN KEY (tenant_id, policy_version) REFERENCES support_sla_policy(tenant_id, version)
);

CREATE TABLE IF NOT EXISTS commercial_audit_event (
  sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
  previous_digest TEXT,
  event_digest TEXT NOT NULL UNIQUE CHECK(length(event_digest)=64),
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS commercial_audit_tenant_time
  ON commercial_audit_event(tenant_id, occurred_at, sequence_id);
CREATE TABLE IF NOT EXISTS commercial_audit_export (
  export_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  event_count INTEGER NOT NULL CHECK(event_count >= 0),
  ending_digest TEXT,
  manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64),
  signer_identity TEXT NOT NULL,
  receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64),
  manifest_json TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, period_start, period_end, manifest_digest)
);

CREATE TABLE IF NOT EXISTS customer_invoice (
  invoice_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  payment_intent_id TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  invoice_code TEXT NOT NULL,
  invoice_type TEXT NOT NULL CHECK(invoice_type IN ('vat_electronic_normal', 'vat_electronic_special', 'commercial_receipt')),
  invoice_category TEXT NOT NULL CHECK(invoice_category IN ('blue', 'red')),
  original_invoice_id TEXT REFERENCES customer_invoice(invoice_id),
  status TEXT NOT NULL CHECK(status IN ('DRAFT', 'APPLIED', 'ISSUED', 'RED_NOTED', 'VOIDED', 'REJECTED')),
  currency TEXT NOT NULL CHECK(length(currency) = 3),
  untaxed_amount_minor INTEGER NOT NULL,
  tax_amount_minor INTEGER NOT NULL,
  total_amount_minor INTEGER NOT NULL,
  buyer_type TEXT NOT NULL CHECK(buyer_type IN ('enterprise', 'individual', 'government')),
  buyer_name TEXT NOT NULL,
  buyer_tax_number TEXT,
  buyer_address_phone TEXT,
  buyer_bank_account TEXT,
  recipient_email TEXT,
  recipient_phone TEXT,
  seller_name TEXT NOT NULL,
  seller_tax_number TEXT NOT NULL,
  seller_address_phone TEXT,
  seller_bank_account TEXT,
  operator TEXT NOT NULL,
  checker TEXT,
  payee TEXT,
  issued_at TEXT,
  voided_at TEXT,
  verification_code TEXT,
  download_url TEXT,
  idempotency_key TEXT,
  idempotency_payload_digest TEXT CHECK(idempotency_payload_digest IS NULL OR length(idempotency_payload_digest) = 64),
  split_batch_id TEXT,
  split_index INTEGER NOT NULL DEFAULT 1,
  split_count INTEGER NOT NULL DEFAULT 1,
  settled_amount_minor INTEGER NOT NULL DEFAULT 0,
  settlement_status TEXT NOT NULL DEFAULT 'UNSETTLED' CHECK(settlement_status IN ('UNSETTLED', 'PARTIALLY_SETTLED', 'FULLY_SETTLED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, invoice_number)
);

CREATE INDEX IF NOT EXISTS idx_customer_invoice_tenant_pi ON customer_invoice(tenant_id, payment_intent_id);
CREATE INDEX IF NOT EXISTS idx_customer_invoice_tenant_status ON customer_invoice(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_customer_invoice_tenant_idempotency ON customer_invoice(tenant_id, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_customer_invoice_tenant_split ON customer_invoice(tenant_id, split_batch_id);

CREATE TABLE IF NOT EXISTS customer_invoice_item (
  item_id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),
  item_name TEXT NOT NULL,
  specification TEXT,
  unit TEXT,
  quantity INTEGER NOT NULL,
  unit_price_minor INTEGER NOT NULL,
  amount_minor INTEGER NOT NULL,
  tax_rate_basis_points INTEGER NOT NULL CHECK(tax_rate_basis_points >= 0),
  tax_amount_minor INTEGER NOT NULL,
  tax_classification_code TEXT
);

CREATE TABLE IF NOT EXISTS customer_buyer_title (
  title_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  buyer_type TEXT NOT NULL CHECK(buyer_type IN ('enterprise', 'individual', 'government')),
  buyer_name TEXT NOT NULL,
  buyer_tax_number TEXT,
  buyer_address_phone TEXT,
  buyer_bank_account TEXT,
  recipient_email TEXT,
  recipient_phone TEXT,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_invoice_audit (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest) = 64),
  previous_digest TEXT CHECK(previous_digest IS NULL OR length(previous_digest) = 64),
  event_digest TEXT NOT NULL CHECK(length(event_digest) = 64),
  payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_customer_invoice_audit_tenant_inv ON customer_invoice_audit(tenant_id, invoice_id);

CREATE TABLE IF NOT EXISTS merchant_settlement_config (
  config_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  currency TEXT NOT NULL CHECK(length(currency) = 3),
  settlement_cycle TEXT NOT NULL CHECK(settlement_cycle IN ('T_PLUS_0', 'T_PLUS_1', 'WEEKLY', 'MONTHLY')),
  minimum_payout_minor INTEGER NOT NULL CHECK(minimum_payout_minor >= 0),
  commission_basis_points INTEGER NOT NULL CHECK(commission_basis_points BETWEEN 0 AND 10000),
  channel_fee_basis_points INTEGER NOT NULL CHECK(channel_fee_basis_points BETWEEN 0 AND 10000),
  reserve_holdback_basis_points INTEGER NOT NULL CHECK(reserve_holdback_basis_points BETWEEN 0 AND 10000),
  bank_name TEXT NOT NULL,
  bank_account_number TEXT NOT NULL,
  bank_account_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'SUSPENDED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, project_id, currency)
);

CREATE TABLE IF NOT EXISTS merchant_settlement_batch (
  batch_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  batch_number TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  currency TEXT NOT NULL CHECK(length(currency) = 3),
  total_transactions INTEGER NOT NULL CHECK(total_transactions >= 0),
  gross_captured_minor INTEGER NOT NULL CHECK(gross_captured_minor >= 0),
  gross_refunded_minor INTEGER NOT NULL CHECK(gross_refunded_minor >= 0),
  net_captured_minor INTEGER NOT NULL CHECK(net_captured_minor >= 0),
  channel_fee_minor INTEGER NOT NULL CHECK(channel_fee_minor >= 0),
  platform_commission_minor INTEGER NOT NULL CHECK(platform_commission_minor >= 0),
  reserve_holdback_minor INTEGER NOT NULL CHECK(reserve_holdback_minor >= 0),
  net_payout_minor INTEGER NOT NULL CHECK(net_payout_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('DRAFT', 'CALCULATED', 'PENDING_APPROVAL', 'APPROVED', 'EXECUTED', 'REJECTED', 'ON_HOLD')),
  created_by TEXT NOT NULL,
  approved_by TEXT,
  executed_by TEXT,
  bank_reference_id TEXT,
  executed_at TEXT,
  payout_instruction_digest TEXT CHECK(payout_instruction_digest IS NULL OR length(payout_instruction_digest) = 64),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, batch_number)
);

CREATE INDEX IF NOT EXISTS idx_settlement_batch_tenant_period ON merchant_settlement_batch(tenant_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_settlement_batch_tenant_status ON merchant_settlement_batch(tenant_id, status);

CREATE TABLE IF NOT EXISTS merchant_settlement_audit (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest) = 64),
  previous_digest TEXT CHECK(previous_digest IS NULL OR length(previous_digest) = 64),
  event_digest TEXT NOT NULL CHECK(length(event_digest) = 64),
  payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_settlement_audit_tenant_batch ON merchant_settlement_audit(tenant_id, batch_id);

CREATE TABLE IF NOT EXISTS merchant_dispute (
  dispute_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  payment_intent_id TEXT NOT NULL,
  dispute_amount_minor INTEGER NOT NULL CHECK(dispute_amount_minor > 0),
  currency TEXT NOT NULL CHECK(length(currency) = 3),
  reason_code TEXT NOT NULL CHECK(reason_code IN ('FRAUDULENT', 'UNRECOGNIZED', 'PRODUCT_NOT_RECEIVED', 'SUBSCRIPTION_CANCELED', 'DUPLICATE', 'OTHER')),
  status TEXT NOT NULL CHECK(status IN ('NEEDS_RESPONSE', 'UNDER_REVIEW', 'WON', 'LOST')),
  evidence_due_at TEXT NOT NULL,
  evidence_json TEXT,
  lost_fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(lost_fee_minor >= 0),
  resolved_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, payment_intent_id)
);

CREATE INDEX IF NOT EXISTS idx_merchant_dispute_tenant_status ON merchant_dispute(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_merchant_dispute_tenant_pi ON merchant_dispute(tenant_id, payment_intent_id);

CREATE TABLE IF NOT EXISTS merchant_dispute_audit (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  dispute_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK(length(payload_digest) = 64),
  previous_digest TEXT CHECK(previous_digest IS NULL OR length(previous_digest) = 64),
  event_digest TEXT NOT NULL CHECK(length(event_digest) = 64),
  payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dispute_audit_tenant_disp ON merchant_dispute_audit(tenant_id, dispute_id);

CREATE TABLE IF NOT EXISTS customer_invoice_quota (
  tenant_id TEXT PRIMARY KEY,
  monthly_tax_quota_minor INTEGER NOT NULL CHECK(monthly_tax_quota_minor > 0),
  single_invoice_limit_minor INTEGER NOT NULL CHECK(single_invoice_limit_minor > 0),
  quota_version TEXT NOT NULL CHECK(quota_version IN ('WAN', 'SHI_WAN', 'BAI_WAN', 'QIAN_WAN', 'UNLIMITED')),
  auto_split_enabled INTEGER NOT NULL DEFAULT 1 CHECK(auto_split_enabled IN (0, 1)),
  alarm_threshold_pct INTEGER NOT NULL DEFAULT 85 CHECK(alarm_threshold_pct BETWEEN 1 AND 100),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_invoice_self_service (
  session_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  payment_intent_id TEXT NOT NULL,
  captured_amount_minor INTEGER NOT NULL CHECK(captured_amount_minor > 0),
  currency TEXT NOT NULL CHECK(length(currency) = 3),
  seller_name TEXT NOT NULL,
  seller_tax_number TEXT NOT NULL,
  session_token TEXT NOT NULL UNIQUE,
  session_token_digest TEXT NOT NULL CHECK(length(session_token_digest) = 64),
  qr_code_url TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REDEEMED', 'EXPIRED', 'CANCELLED')),
  redeemed_invoice_id TEXT,
  redeemed_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, payment_intent_id)
);

CREATE INDEX IF NOT EXISTS idx_self_service_token ON customer_invoice_self_service(session_token);
CREATE INDEX IF NOT EXISTS idx_self_service_tenant_pi ON customer_invoice_self_service(tenant_id, payment_intent_id);
CREATE INDEX IF NOT EXISTS idx_self_service_tenant_status ON customer_invoice_self_service(tenant_id, status);

CREATE TABLE IF NOT EXISTS customer_invoice_payment_ref (
  ref_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),
  payment_intent_id TEXT NOT NULL,
  invoiced_amount_minor INTEGER NOT NULL CHECK(invoiced_amount_minor >= 0),
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, invoice_id, payment_intent_id)
);
CREATE INDEX IF NOT EXISTS idx_inv_pay_ref_tenant_pi ON customer_invoice_payment_ref(tenant_id, payment_intent_id);

CREATE TABLE IF NOT EXISTS customer_invoice_delivery (
  delivery_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),
  channel TEXT NOT NULL CHECK(channel IN ('EMAIL', 'SMS', 'WEBHOOK')),
  destination TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'SENT', 'DELIVERED', 'FAILED')),
  attempts INTEGER NOT NULL DEFAULT 1,
  error_message TEXT,
  payload_digest TEXT,
  sent_at TEXT,
  delivered_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_delivery_tenant_inv ON customer_invoice_delivery(tenant_id, invoice_id);

CREATE TABLE IF NOT EXISTS customer_invoice_reimbursement (
  reimbursement_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),
  claim_id TEXT NOT NULL,
  claimant TEXT NOT NULL,
  department TEXT NOT NULL,
  expense_category TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  status TEXT NOT NULL CHECK(status IN ('SUBMITTED', 'APPROVED', 'REJECTED')),
  claimed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, invoice_id)
);
CREATE INDEX IF NOT EXISTS idx_inv_reimb_tenant_claim ON customer_invoice_reimbursement(tenant_id, claim_id);

CREATE TABLE IF NOT EXISTS customer_invoice_settlement_reconciliation (
  reconciliation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL REFERENCES customer_invoice(invoice_id),
  settlement_ref TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  reconciled_by TEXT NOT NULL,
  notes TEXT,
  reconciled_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inv_settle_reconcile_tenant_inv ON customer_invoice_settlement_reconciliation(tenant_id, invoice_id);

CREATE TABLE IF NOT EXISTS commercial_contract (
  contract_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  buyer_name TEXT NOT NULL,
  buyer_tax_number TEXT,
  seller_name TEXT NOT NULL,
  seller_tax_number TEXT NOT NULL,
  total_amount_minor INTEGER NOT NULL CHECK(total_amount_minor > 0),
  currency TEXT NOT NULL DEFAULT 'CNY',
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'COMPLETED', 'TERMINATED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contract_tenant ON commercial_contract(tenant_id);

CREATE TABLE IF NOT EXISTS contract_milestone (
  milestone_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  contract_id TEXT NOT NULL REFERENCES commercial_contract(contract_id),
  seq_order INTEGER NOT NULL CHECK(seq_order >= 1),
  name TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  invoiced_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(invoiced_amount_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'PARTIALLY_INVOICED', 'FULLY_INVOICED', 'SETTLED')),
  due_date TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, contract_id, seq_order)
);
CREATE INDEX IF NOT EXISTS idx_contract_milestone_cid ON contract_milestone(tenant_id, contract_id);

CREATE TABLE IF NOT EXISTS contract_fulfillment_ledger (
  entry_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  contract_id TEXT NOT NULL REFERENCES commercial_contract(contract_id),
  milestone_id TEXT REFERENCES contract_milestone(milestone_id),
  invoice_id TEXT,
  entry_type TEXT NOT NULL CHECK(entry_type IN ('MILESTONE_INVOICED', 'PAYMENT_APPLIED', 'ADJUSTMENT')),
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  actor_id TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contract_ledger_cid ON contract_fulfillment_ledger(tenant_id, contract_id);

CREATE TABLE IF NOT EXISTS tax_withholding_certificate (
  certificate_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  certificate_number TEXT NOT NULL UNIQUE,
  payee_type TEXT NOT NULL CHECK(payee_type IN ('INDIVIDUAL', 'ENTERPRISE_NON_RESIDENT')),
  payee_name TEXT NOT NULL,
  payee_id_type TEXT NOT NULL DEFAULT 'RESIDENT_ID',
  payee_id_number TEXT NOT NULL,
  income_type TEXT NOT NULL CHECK(income_type IN ('LABOR_SERVICE', 'ROYALTY', 'PROPERTY_LEASING', 'NON_RESIDENT_WHT')),
  gross_amount_minor INTEGER NOT NULL CHECK(gross_amount_minor > 0),
  statutory_deduction_minor INTEGER NOT NULL CHECK(statutory_deduction_minor >= 0),
  taxable_income_minor INTEGER NOT NULL CHECK(taxable_income_minor >= 0),
  tax_rate_basis_points INTEGER NOT NULL CHECK(tax_rate_basis_points >= 0),
  quick_deduction_minor INTEGER NOT NULL CHECK(quick_deduction_minor >= 0),
  tax_withheld_minor INTEGER NOT NULL CHECK(tax_withheld_minor >= 0),
  net_payout_minor INTEGER NOT NULL CHECK(net_payout_minor >= 0),
  filing_status TEXT NOT NULL CHECK(filing_status IN ('RECORDED', 'SUBMITTED', 'REMITTED')),
  digest TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tax_withhold_tenant ON tax_withholding_certificate(tenant_id, filing_status);

CREATE TABLE IF NOT EXISTS tax_remittance_batch (
  batch_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  tax_period TEXT NOT NULL,
  item_count INTEGER NOT NULL CHECK(item_count > 0),
  total_gross_minor INTEGER NOT NULL CHECK(total_gross_minor >= 0),
  total_tax_withheld_minor INTEGER NOT NULL CHECK(total_tax_withheld_minor >= 0),
  batch_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PREPARED', 'DECLARED', 'ACCEPTED')),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tax_remit_tenant_period ON tax_remittance_batch(tenant_id, tax_period);

CREATE TABLE IF NOT EXISTS customs_payment_declaration (
  declaration_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  customs_code TEXT NOT NULL,
  ebp_code TEXT NOT NULL,
  ebc_code TEXT NOT NULL,
  order_no TEXT NOT NULL,
  payment_intent_id TEXT NOT NULL,
  payer_name TEXT NOT NULL,
  payer_id_type TEXT NOT NULL DEFAULT '1',
  payer_id_number TEXT NOT NULL,
  payer_phone TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT '142',
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'REPORTED', 'CUSTOMS_ACCEPTED', 'CUSTOMS_REJECTED')),
  customs_receipt_code TEXT,
  customs_receipt_message TEXT,
  signature_digest TEXT NOT NULL,
  declared_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, order_no, payment_intent_id)
);
CREATE INDEX IF NOT EXISTS idx_customs_decl_tenant_order ON customs_payment_declaration(tenant_id, order_no);

CREATE TABLE IF NOT EXISTS customs_declaration_log (
  log_id TEXT PRIMARY KEY,
  declaration_id TEXT NOT NULL REFERENCES customs_payment_declaration(declaration_id),
  action TEXT NOT NULL,
  request_payload TEXT NOT NULL,
  response_payload TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customs_log_decl ON customs_declaration_log(declaration_id);

CREATE TABLE IF NOT EXISTS treasury_pool (
  pool_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL UNIQUE,
  pool_name TEXT NOT NULL,
  master_account_id TEXT NOT NULL,
  master_balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(master_balance_minor >= 0),
  currency TEXT NOT NULL DEFAULT 'CNY',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_treasury_pool_tenant ON treasury_pool(tenant_id);

CREATE TABLE IF NOT EXISTS treasury_virtual_account (
  va_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  pool_id TEXT NOT NULL REFERENCES treasury_pool(pool_id),
  account_number TEXT NOT NULL UNIQUE,
  account_name TEXT NOT NULL,
  entity_type TEXT NOT NULL CHECK(entity_type IN ('STORE', 'BRANCH', 'DISTRIBUTOR', 'MERCHANT')),
  balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(balance_minor >= 0),
  sweep_policy TEXT NOT NULL CHECK(sweep_policy IN ('ZERO_BALANCE', 'TARGET_BALANCE', 'MANUAL')),
  target_balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(target_balance_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'FROZEN', 'CLOSED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_treasury_va_tenant_pool ON treasury_virtual_account(tenant_id, pool_id);

CREATE TABLE IF NOT EXISTS treasury_transfer_journal (
  journal_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  pool_id TEXT NOT NULL REFERENCES treasury_pool(pool_id),
  source_account_id TEXT NOT NULL,
  dest_account_id TEXT NOT NULL,
  transfer_type TEXT NOT NULL CHECK(transfer_type IN ('SWEEP', 'ALLOCATE', 'DEPOSIT', 'WITHDRAWAL')),
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  source_balance_after_minor INTEGER NOT NULL CHECK(source_balance_after_minor >= 0),
  dest_balance_after_minor INTEGER NOT NULL CHECK(dest_balance_after_minor >= 0),
  actor_id TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_treasury_journal_tenant_pool ON treasury_transfer_journal(tenant_id, pool_id);

CREATE TABLE IF NOT EXISTS fx_rate_matrix (
  matrix_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  base_currency TEXT NOT NULL CHECK(length(base_currency)=3),
  target_currency TEXT NOT NULL CHECK(length(target_currency)=3),
  spot_rate_units INTEGER NOT NULL CHECK(spot_rate_units > 0),
  spread_basis_points INTEGER NOT NULL DEFAULT 50 CHECK(spread_basis_points >= 0),
  effective_at TEXT NOT NULL,
  UNIQUE(tenant_id, base_currency, target_currency)
);
CREATE INDEX IF NOT EXISTS idx_fx_matrix_tenant_cur ON fx_rate_matrix(tenant_id, base_currency, target_currency);

CREATE TABLE IF NOT EXISTS fx_quote_lock (
  quote_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  base_currency TEXT NOT NULL CHECK(length(base_currency)=3),
  target_currency TEXT NOT NULL CHECK(length(target_currency)=3),
  source_amount_minor INTEGER NOT NULL CHECK(source_amount_minor > 0),
  target_amount_minor INTEGER NOT NULL CHECK(target_amount_minor > 0),
  spot_rate_units INTEGER NOT NULL CHECK(spot_rate_units > 0),
  spread_basis_points INTEGER NOT NULL CHECK(spread_basis_points >= 0),
  effective_rate_units INTEGER NOT NULL CHECK(effective_rate_units > 0),
  status TEXT NOT NULL CHECK(status IN ('LOCKED', 'REDEEMED', 'EXPIRED', 'CANCELLED')),
  expires_at TEXT NOT NULL,
  redeemed_at TEXT,
  payment_intent_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fx_quote_tenant_status ON fx_quote_lock(tenant_id, status);

CREATE TABLE IF NOT EXISTS fx_conversion_journal (
  conversion_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  quote_id TEXT NOT NULL REFERENCES fx_quote_lock(quote_id),
  payment_intent_id TEXT NOT NULL,
  base_currency TEXT NOT NULL CHECK(length(base_currency)=3),
  target_currency TEXT NOT NULL CHECK(length(target_currency)=3),
  source_amount_minor INTEGER NOT NULL CHECK(source_amount_minor > 0),
  target_amount_minor INTEGER NOT NULL CHECK(target_amount_minor > 0),
  executed_rate_units INTEGER NOT NULL CHECK(executed_rate_units > 0),
  hedged INTEGER NOT NULL DEFAULT 0 CHECK(hedged IN (0, 1)),
  executed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fx_journal_tenant_pi ON fx_conversion_journal(tenant_id, payment_intent_id);

CREATE TABLE IF NOT EXISTS b2b_credit_facility (
  facility_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  buyer_id TEXT NOT NULL,
  buyer_name TEXT NOT NULL,
  credit_limit_minor INTEGER NOT NULL CHECK(credit_limit_minor > 0),
  drawn_balance_minor INTEGER NOT NULL DEFAULT 0 CHECK(drawn_balance_minor >= 0),
  currency TEXT NOT NULL DEFAULT 'CNY' CHECK(length(currency)=3),
  credit_tier TEXT NOT NULL CHECK(credit_tier IN ('STANDARD', 'PRIME', 'ENTERPRISE')),
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'FROZEN', 'CLOSED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, buyer_id)
);
CREATE INDEX IF NOT EXISTS idx_b2b_facility_tenant_buyer ON b2b_credit_facility(tenant_id, buyer_id);

CREATE TABLE IF NOT EXISTS b2b_purchase_order (
  po_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  facility_id TEXT NOT NULL REFERENCES b2b_credit_facility(facility_id),
  po_number TEXT NOT NULL,
  buyer_id TEXT NOT NULL,
  seller_name TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  payment_terms TEXT NOT NULL CHECK(payment_terms IN ('DUE_ON_RECEIPT', 'NET_15', 'NET_30', 'NET_60', 'NET_90')),
  issue_date TEXT NOT NULL,
  due_date TEXT NOT NULL,
  settled_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(settled_amount_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('ISSUED', 'PARTIALLY_SETTLED', 'SETTLED', 'CANCELLED', 'OVERDUE')),
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, po_number)
);
CREATE INDEX IF NOT EXISTS idx_b2b_po_tenant_buyer ON b2b_purchase_order(tenant_id, buyer_id);
CREATE INDEX IF NOT EXISTS idx_b2b_po_tenant_status ON b2b_purchase_order(tenant_id, status);

CREATE TABLE IF NOT EXISTS b2b_credit_drawdown_ledger (
  entry_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  facility_id TEXT NOT NULL REFERENCES b2b_credit_facility(facility_id),
  po_id TEXT REFERENCES b2b_purchase_order(po_id),
  action TEXT NOT NULL CHECK(action IN ('DRAWDOWN', 'REPAYMENT', 'LIMIT_ADJUSTMENT', 'PENALTY_ACCRUED')),
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  balance_after_minor INTEGER NOT NULL CHECK(balance_after_minor >= 0),
  notes TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_b2b_ledger_facility ON b2b_credit_drawdown_ledger(facility_id);

CREATE TABLE IF NOT EXISTS mass_payout_batch (
  batch_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  batch_name TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY' CHECK(length(currency)=3),
  total_count INTEGER NOT NULL CHECK(total_count > 0),
  total_amount_minor INTEGER NOT NULL CHECK(total_amount_minor > 0),
  total_fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(total_fee_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'PROCESSING', 'COMPLETED', 'PARTIALLY_FAILED', 'REJECTED')),
  maker_id TEXT NOT NULL,
  checker_id TEXT,
  approved_at TEXT,
  batch_digest TEXT NOT NULL CHECK(length(batch_digest)=64),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payout_batch_tenant_status ON mass_payout_batch(tenant_id, status);

CREATE TABLE IF NOT EXISTS mass_payout_item (
  item_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  batch_id TEXT NOT NULL REFERENCES mass_payout_batch(batch_id),
  recipient_id TEXT NOT NULL,
  recipient_name TEXT NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('BANK_WIRE', 'ALIPAY', 'WECHAT_PAY', 'PAYPAL', 'SEPA')),
  account_identifier TEXT NOT NULL,
  amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
  fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(fee_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'PROCESSING', 'SUCCESS', 'FAILED', 'REVERSED')),
  failure_reason TEXT,
  channel_reference TEXT,
  executed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payout_item_batch ON mass_payout_item(batch_id);

CREATE TABLE IF NOT EXISTS card_vault (
  vault_token TEXT PRIMARY KEY,
  network_token TEXT UNIQUE,
  tenant_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  card_brand TEXT NOT NULL CHECK(card_brand IN ('VISA', 'MASTERCARD', 'AMEX', 'UNIONPAY', 'JCB', 'DISCOVER')),
  bin_first6 TEXT NOT NULL CHECK(length(bin_first6)=6),
  last4 TEXT NOT NULL CHECK(length(last4)=4),
  exp_month INTEGER NOT NULL CHECK(exp_month BETWEEN 1 AND 12),
  exp_year INTEGER NOT NULL CHECK(exp_year >= 2024),
  cardholder_name TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64),
  encrypted_pan_envelope TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
  token_requester_id TEXT NOT NULL DEFAULT 'TRID_ELMPAY_400',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, customer_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_card_vault_tenant_cust ON card_vault(tenant_id, customer_id);

CREATE TABLE IF NOT EXISTS card_updater_event (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  vault_token TEXT NOT NULL REFERENCES card_vault(vault_token),
  event_type TEXT NOT NULL CHECK(event_type IN ('EXPIRY_UPDATE', 'CARD_REPLACED', 'ACCOUNT_CLOSED', 'CONTACT_CARDHOLDER')),
  old_exp_month INTEGER,
  old_exp_year INTEGER,
  new_exp_month INTEGER,
  new_exp_year INTEGER,
  new_last4 TEXT,
  processed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_card_updater_token ON card_updater_event(vault_token);

CREATE TABLE IF NOT EXISTS routing_provider_profile (
  profile_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  provider_name TEXT NOT NULL,
  supported_methods_csv TEXT NOT NULL,
  supported_currencies_csv TEXT NOT NULL,
  min_amount_minor INTEGER NOT NULL DEFAULT 1 CHECK(min_amount_minor >= 0),
  max_amount_minor INTEGER NOT NULL CHECK(max_amount_minor > 0),
  fee_basis_points INTEGER NOT NULL CHECK(fee_basis_points >= 0),
  fixed_fee_minor INTEGER NOT NULL DEFAULT 0 CHECK(fixed_fee_minor >= 0),
  health_status TEXT NOT NULL CHECK(health_status IN ('HEALTHY', 'DEGRADED', 'CIRCUIT_BROKEN')),
  priority_rank INTEGER NOT NULL DEFAULT 100,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(tenant_id, provider_id)
);
CREATE INDEX IF NOT EXISTS idx_routing_profile_tenant ON routing_provider_profile(tenant_id, health_status);

CREATE TABLE IF NOT EXISTS smart_routing_decision_log (
  decision_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  payment_intent_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL,
  payment_method TEXT NOT NULL,
  card_brand TEXT,
  selected_provider_id TEXT NOT NULL,
  estimated_fee_minor INTEGER NOT NULL,
  cascade_routes_json TEXT NOT NULL,
  routed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_routing_decision_pi ON smart_routing_decision_log(tenant_id, payment_intent_id);

CREATE TABLE IF NOT EXISTS merchant_fee_schedule (
  schedule_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL UNIQUE,
  pricing_model TEXT NOT NULL CHECK(pricing_model IN ('BLENDED', 'TIERED_VOLUME', 'INTERCHANGE_PLUS_PLUS')),
  tiers_json TEXT,
  markup_basis_points INTEGER NOT NULL DEFAULT 30 CHECK(markup_basis_points >= 0),
  fixed_fee_minor INTEGER NOT NULL DEFAULT 30 CHECK(fixed_fee_minor >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS merchant_fee_journal (
  journal_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  transaction_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL,
  pricing_model TEXT NOT NULL,
  gross_fee_minor INTEGER NOT NULL,
  interchange_cost_minor INTEGER NOT NULL DEFAULT 0,
  scheme_assessment_minor INTEGER NOT NULL DEFAULT 0,
  net_margin_minor INTEGER NOT NULL,
  billed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fee_journal_tenant_txn ON merchant_fee_journal(tenant_id, transaction_id);

CREATE TABLE IF NOT EXISTS webhook_endpoint_subscription (
  endpoint_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret_key TEXT NOT NULL,
  subscribed_events_csv TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'DISABLED')),
  created_at TEXT NOT NULL,
  UNIQUE(tenant_id, url)
);

CREATE TABLE IF NOT EXISTS webhook_event_queue (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoint_subscription(endpoint_id),
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  signature_header TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'DELIVERED', 'RETRYING', 'DEAD_LETTER')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  last_http_status INTEGER,
  last_error_message TEXT,
  next_delivery_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_queue_status ON webhook_event_queue(tenant_id, status, next_delivery_at);

CREATE TABLE IF NOT EXISTS webhook_dead_letter (
  dead_letter_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE REFERENCES webhook_event_queue(event_id),
  endpoint_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  final_error TEXT NOT NULL,
  replayed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant ON webhook_dead_letter(tenant_id);

CREATE TABLE IF NOT EXISTS marketplace_split_order (
  order_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  captured_amount_minor INTEGER NOT NULL CHECK(captured_amount_minor > 0),
  currency TEXT NOT NULL,
  platform_fee_minor INTEGER NOT NULL CHECK(platform_fee_minor >= 0),
  escrow_status TEXT NOT NULL CHECK(escrow_status IN ('HELD', 'RELEASED', 'REFUNDED', 'PARTIALLY_REFUNDED')),
  hold_until TEXT NOT NULL,
  released_at TEXT,
  refunded_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(refunded_amount_minor >= 0),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_split_order_tenant_status ON marketplace_split_order(tenant_id, escrow_status);

CREATE TABLE IF NOT EXISTS marketplace_split_recipient (
  recipient_split_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  order_id TEXT NOT NULL REFERENCES marketplace_split_order(order_id),
  vendor_id TEXT NOT NULL,
  allocated_amount_minor INTEGER NOT NULL CHECK(allocated_amount_minor > 0),
  settled_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(settled_amount_minor >= 0),
  refunded_amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(refunded_amount_minor >= 0),
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'RELEASED', 'REFUNDED')),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_split_recip_order ON marketplace_split_recipient(order_id);



