-- GENERATED FILE — do not edit by hand.
-- Source of truth: governance/data-architecture.json
-- Regenerate with: python3 scripts/render-data.py

-- 租户隔离：共享库共享表 + 强制行级安全。
-- 会话变量：app.tenant_id
-- 注意 FORCE：不加它时表的属主会绕过策略，而运维脚本正是以属主身份运行的。

ALTER TABLE bank_statement ENABLE ROW LEVEL SECURITY;
ALTER TABLE bank_statement FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS bank_statement_tenant_isolation ON bank_statement;
CREATE POLICY bank_statement_tenant_isolation ON bank_statement
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON bank_statement FROM PUBLIC;
-- bank_statement 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE delivery_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_attempt FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS delivery_attempt_tenant_isolation ON delivery_attempt;
CREATE POLICY delivery_attempt_tenant_isolation ON delivery_attempt
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON delivery_attempt FROM PUBLIC;
-- delivery_attempt 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE delivery_dead_letter ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_dead_letter FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS delivery_dead_letter_tenant_isolation ON delivery_dead_letter;
CREATE POLICY delivery_dead_letter_tenant_isolation ON delivery_dead_letter
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON delivery_dead_letter FROM PUBLIC;
-- delivery_dead_letter 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE delivery_subscription ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_subscription FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS delivery_subscription_tenant_isolation ON delivery_subscription;
CREATE POLICY delivery_subscription_tenant_isolation ON delivery_subscription
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE dispute ENABLE ROW LEVEL SECURITY;
ALTER TABLE dispute FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dispute_tenant_isolation ON dispute;
CREATE POLICY dispute_tenant_isolation ON dispute
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE fee_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE fee_record FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fee_record_tenant_isolation ON fee_record;
CREATE POLICY fee_record_tenant_isolation ON fee_record
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON fee_record FROM PUBLIC;
-- fee_record 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE fx_rate ENABLE ROW LEVEL SECURITY;
ALTER TABLE fx_rate FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fx_rate_tenant_isolation ON fx_rate;
CREATE POLICY fx_rate_tenant_isolation ON fx_rate
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE idempotency_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_key FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS idempotency_key_tenant_isolation ON idempotency_key;
CREATE POLICY idempotency_key_tenant_isolation ON idempotency_key
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE job_lock ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_lock FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS job_lock_tenant_isolation ON job_lock;
CREATE POLICY job_lock_tenant_isolation ON job_lock
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE job_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_run FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS job_run_tenant_isolation ON job_run;
CREATE POLICY job_run_tenant_isolation ON job_run
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON job_run FROM PUBLIC;
-- job_run 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE ledger_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_account FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_account_tenant_isolation ON ledger_account;
CREATE POLICY ledger_account_tenant_isolation ON ledger_account
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE ledger_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_entry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_entry_tenant_isolation ON ledger_entry;
CREATE POLICY ledger_entry_tenant_isolation ON ledger_entry
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON ledger_entry FROM PUBLIC;
-- ledger_entry 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE ledger_transaction ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_transaction FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_transaction_tenant_isolation ON ledger_transaction;
CREATE POLICY ledger_transaction_tenant_isolation ON ledger_transaction
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON ledger_transaction FROM PUBLIC;
-- ledger_transaction 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE merchant ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS merchant_tenant_isolation ON merchant;
CREATE POLICY merchant_tenant_isolation ON merchant
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_event FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_event_tenant_isolation ON outbox_event;
CREATE POLICY outbox_event_tenant_isolation ON outbox_event
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON outbox_event FROM PUBLIC;
-- outbox_event 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE payment_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_attempt FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS payment_attempt_tenant_isolation ON payment_attempt;
CREATE POLICY payment_attempt_tenant_isolation ON payment_attempt
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE payment_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_intent FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS payment_intent_tenant_isolation ON payment_intent;
CREATE POLICY payment_intent_tenant_isolation ON payment_intent
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE pricing_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE pricing_rule FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pricing_rule_tenant_isolation ON pricing_rule;
CREATE POLICY pricing_rule_tenant_isolation ON pricing_rule
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE project ENABLE ROW LEVEL SECURITY;
ALTER TABLE project FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS project_tenant_isolation ON project;
CREATE POLICY project_tenant_isolation ON project
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE provider_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_account FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_account_tenant_isolation ON provider_account;
CREATE POLICY provider_account_tenant_isolation ON provider_account
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE provider_capability ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_capability FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_capability_tenant_isolation ON provider_capability;
CREATE POLICY provider_capability_tenant_isolation ON provider_capability
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE provider_effect_application ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_application FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_effect_application_tenant_policy ON provider_effect_application;
CREATE POLICY provider_effect_application_tenant_policy ON provider_effect_application
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE, DELETE ON provider_effect_application FROM PUBLIC;
-- provider_effect_application 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE provider_effect_expectation ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_expectation FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_effect_expectation_tenant_policy ON provider_effect_expectation;
CREATE POLICY provider_effect_expectation_tenant_policy ON provider_effect_expectation
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE, DELETE ON provider_effect_expectation FROM PUBLIC;
-- provider_effect_expectation 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE provider_effect_target_clock ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_effect_target_clock FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_effect_target_clock_tenant_policy ON provider_effect_target_clock;
CREATE POLICY provider_effect_target_clock_tenant_policy ON provider_effect_target_clock
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE provider_statement ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_statement FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_statement_tenant_isolation ON provider_statement;
CREATE POLICY provider_statement_tenant_isolation ON provider_statement
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON provider_statement FROM PUBLIC;
-- provider_statement 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE provider_webhook_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_webhook_inbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_webhook_inbox_tenant_policy ON provider_webhook_inbox;
CREATE POLICY provider_webhook_inbox_tenant_policy ON provider_webhook_inbox
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE provider_webhook_effect_commit ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_webhook_effect_commit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_webhook_effect_commit_tenant_policy ON provider_webhook_effect_commit;
CREATE POLICY provider_webhook_effect_commit_tenant_policy ON provider_webhook_effect_commit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON provider_webhook_effect_commit FROM PUBLIC;
-- provider_webhook_effect_commit 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE recon_exception ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_tenant_isolation ON recon_exception;
CREATE POLICY recon_exception_tenant_isolation ON recon_exception
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE recon_match ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_match FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_match_tenant_isolation ON recon_match;
CREATE POLICY recon_match_tenant_isolation ON recon_match
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON recon_match FROM PUBLIC;
-- recon_match 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE recon_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_run FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_run_tenant_isolation ON recon_run;
CREATE POLICY recon_run_tenant_isolation ON recon_run
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE refund ENABLE ROW LEVEL SECURITY;
ALTER TABLE refund FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS refund_tenant_isolation ON refund;
CREATE POLICY refund_tenant_isolation ON refund
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE risk_case ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_case FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_case_tenant_isolation ON risk_case;
CREATE POLICY risk_case_tenant_isolation ON risk_case
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE risk_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_decision FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_decision_tenant_isolation ON risk_decision;
CREATE POLICY risk_decision_tenant_isolation ON risk_decision
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON risk_decision FROM PUBLIC;
-- risk_decision 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_list_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_list_entry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_list_entry_tenant_isolation ON risk_list_entry;
CREATE POLICY risk_list_entry_tenant_isolation ON risk_list_entry
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE risk_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_rule FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_rule_tenant_isolation ON risk_rule;
CREATE POLICY risk_rule_tenant_isolation ON risk_rule
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE risk_signal ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_signal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_signal_tenant_isolation ON risk_signal;
CREATE POLICY risk_signal_tenant_isolation ON risk_signal
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON risk_signal FROM PUBLIC;
-- risk_signal 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE routing_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE routing_rule FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS routing_rule_tenant_isolation ON routing_rule;
CREATE POLICY routing_rule_tenant_isolation ON routing_rule
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE scheduled_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_job FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scheduled_job_tenant_isolation ON scheduled_job;
CREATE POLICY scheduled_job_tenant_isolation ON scheduled_job
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE settlement_instruction ENABLE ROW LEVEL SECURITY;
ALTER TABLE settlement_instruction FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS settlement_instruction_tenant_isolation ON settlement_instruction;
CREATE POLICY settlement_instruction_tenant_isolation ON settlement_instruction
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE subscription ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS subscription_tenant_isolation ON subscription;
CREATE POLICY subscription_tenant_isolation ON subscription
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- tenant: 不做行级隔离 — tenant 表本身就是租户目录；对它做行级隔离会让租户无法被创建或查询

ALTER TABLE admin_access_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_access_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_access_audit_tenant_policy ON admin_access_audit;
CREATE POLICY admin_access_audit_tenant_policy ON admin_access_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_access_audit FROM PUBLIC;
-- admin_access_audit 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_action_diagnostic_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_diagnostic_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_action_diagnostic_audit_tenant_policy ON admin_action_diagnostic_audit;
CREATE POLICY admin_action_diagnostic_audit_tenant_policy ON admin_action_diagnostic_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_action_diagnostic_audit FROM PUBLIC;
-- admin_action_diagnostic_audit 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_action_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_dispatch FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_action_dispatch_tenant_policy ON admin_action_dispatch;
CREATE POLICY admin_action_dispatch_tenant_policy ON admin_action_dispatch
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE admin_action_effect_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_effect_receipt FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_action_effect_receipt_tenant_policy ON admin_action_effect_receipt;
CREATE POLICY admin_action_effect_receipt_tenant_policy ON admin_action_effect_receipt
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_action_effect_receipt FROM PUBLIC;
-- admin_action_effect_receipt 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_approval FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_approval_tenant_policy ON admin_approval;
CREATE POLICY admin_approval_tenant_policy ON admin_approval
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_approval FROM PUBLIC;
-- admin_approval 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_approval_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_approval_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_approval_audit_tenant_policy ON admin_approval_audit;
CREATE POLICY admin_approval_audit_tenant_policy ON admin_approval_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_approval_audit FROM PUBLIC;
-- admin_approval_audit 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_diagnostic_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_diagnostic_snapshot FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_diagnostic_snapshot_tenant_policy ON admin_diagnostic_snapshot;
CREATE POLICY admin_diagnostic_snapshot_tenant_policy ON admin_diagnostic_snapshot
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_diagnostic_snapshot FROM PUBLIC;
-- admin_diagnostic_snapshot 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_dispatch_signal ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_dispatch_signal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_dispatch_signal_tenant_policy ON admin_dispatch_signal;
CREATE POLICY admin_dispatch_signal_tenant_policy ON admin_dispatch_signal
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE admin_domain_command ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_domain_command FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_domain_command_tenant_policy ON admin_domain_command;
CREATE POLICY admin_domain_command_tenant_policy ON admin_domain_command
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_domain_command FROM PUBLIC;
-- admin_domain_command 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_domain_command_signal ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_domain_command_signal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_domain_command_signal_tenant_policy ON admin_domain_command_signal;
CREATE POLICY admin_domain_command_signal_tenant_policy ON admin_domain_command_signal
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- admin_dpop_nonce: 不做行级隔离 — platform control metadata has no tenant payload and is guarded by its owning service role
REVOKE UPDATE, DELETE ON admin_dpop_nonce FROM PUBLIC;
-- admin_dpop_nonce 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_dpop_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_dpop_replay FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_dpop_replay_tenant_policy ON admin_dpop_replay;
CREATE POLICY admin_dpop_replay_tenant_policy ON admin_dpop_replay
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_dpop_replay FROM PUBLIC;
-- admin_dpop_replay 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE admin_rollout_stage_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_rollout_stage_approval FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_rollout_stage_approval_tenant_policy ON admin_rollout_stage_approval;
CREATE POLICY admin_rollout_stage_approval_tenant_policy ON admin_rollout_stage_approval
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON admin_rollout_stage_approval FROM PUBLIC;
-- admin_rollout_stage_approval 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE consumer_event_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumer_event_inbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS consumer_event_inbox_tenant_policy ON consumer_event_inbox;
CREATE POLICY consumer_event_inbox_tenant_policy ON consumer_event_inbox
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON consumer_event_inbox FROM PUBLIC;
-- consumer_event_inbox 是仅追加表：更新与删除在权限层就被拿掉。

-- data_table_ownership: 不做行级隔离 — platform control metadata has no tenant payload and is guarded by its owning service role
REVOKE UPDATE, DELETE ON data_table_ownership FROM PUBLIC;
-- data_table_ownership 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE event_aggregate_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_aggregate_revision FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS event_aggregate_revision_tenant_policy ON event_aggregate_revision;
CREATE POLICY event_aggregate_revision_tenant_policy ON event_aggregate_revision
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON event_aggregate_revision FROM PUBLIC;
-- event_aggregate_revision 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE financial_admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_admin_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_admin_audit_tenant_policy ON financial_admin_audit;
CREATE POLICY financial_admin_audit_tenant_policy ON financial_admin_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON financial_admin_audit FROM PUBLIC;
-- financial_admin_audit 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE financial_export ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_export FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_export_tenant_policy ON financial_export;
CREATE POLICY financial_export_tenant_policy ON financial_export
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON financial_export FROM PUBLIC;
-- financial_export 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE financial_runtime_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_runtime_job FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS financial_runtime_job_tenant_policy ON financial_runtime_job;
CREATE POLICY financial_runtime_job_tenant_policy ON financial_runtime_job
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE ledger_event_revision_guard ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_event_revision_guard FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_event_revision_guard_tenant_policy ON ledger_event_revision_guard;
CREATE POLICY ledger_event_revision_guard_tenant_policy ON ledger_event_revision_guard
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON ledger_event_revision_guard FROM PUBLIC;
-- ledger_event_revision_guard 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE ledger_posting_account_mapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_posting_account_mapping FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_posting_account_mapping_tenant_policy ON ledger_posting_account_mapping;
CREATE POLICY ledger_posting_account_mapping_tenant_policy ON ledger_posting_account_mapping
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON ledger_posting_account_mapping FROM PUBLIC;
-- ledger_posting_account_mapping 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE ledger_posting_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger_posting_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ledger_posting_policy_tenant_policy ON ledger_posting_policy;
CREATE POLICY ledger_posting_policy_tenant_policy ON ledger_posting_policy
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON ledger_posting_policy FROM PUBLIC;
-- ledger_posting_policy 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE recon_exception_action ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception_action FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_action_tenant_policy ON recon_exception_action;
CREATE POLICY recon_exception_action_tenant_policy ON recon_exception_action
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON recon_exception_action FROM PUBLIC;
-- recon_exception_action 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE recon_exception_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception_current FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_current_tenant_policy ON recon_exception_current;
CREATE POLICY recon_exception_current_tenant_policy ON recon_exception_current
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON recon_exception_current FROM PUBLIC;
-- recon_exception_current 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE recon_exception_origin ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_exception_origin FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recon_exception_origin_tenant_policy ON recon_exception_origin;
CREATE POLICY recon_exception_origin_tenant_policy ON recon_exception_origin
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON recon_exception_origin FROM PUBLIC;
-- recon_exception_origin 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE reconciliation_fact_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliation_fact_snapshot FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reconciliation_fact_snapshot_tenant_policy ON reconciliation_fact_snapshot;
CREATE POLICY reconciliation_fact_snapshot_tenant_policy ON reconciliation_fact_snapshot
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON reconciliation_fact_snapshot FROM PUBLIC;
-- reconciliation_fact_snapshot 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE reconciliation_fact_snapshot_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliation_fact_snapshot_member FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reconciliation_fact_snapshot_member_tenant_policy ON reconciliation_fact_snapshot_member;
CREATE POLICY reconciliation_fact_snapshot_member_tenant_policy ON reconciliation_fact_snapshot_member
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON reconciliation_fact_snapshot_member FROM PUBLIC;
-- reconciliation_fact_snapshot_member 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE reconciliation_schedule_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliation_schedule_cursor FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reconciliation_schedule_cursor_tenant_policy ON reconciliation_schedule_cursor;
CREATE POLICY reconciliation_schedule_cursor_tenant_policy ON reconciliation_schedule_cursor
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON reconciliation_schedule_cursor FROM PUBLIC;
-- reconciliation_schedule_cursor 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_audit_tenant_policy ON risk_audit;
CREATE POLICY risk_audit_tenant_policy ON risk_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_audit FROM PUBLIC;
-- risk_audit 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_operation ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_operation FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_operation_tenant_policy ON risk_operation;
CREATE POLICY risk_operation_tenant_policy ON risk_operation
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_operation FROM PUBLIC;
-- risk_operation 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_outbox_tenant_policy ON risk_outbox;
CREATE POLICY risk_outbox_tenant_policy ON risk_outbox
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_outbox FROM PUBLIC;
-- risk_outbox 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_rule_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_rule_set FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_rule_set_tenant_policy ON risk_rule_set;
CREATE POLICY risk_rule_set_tenant_policy ON risk_rule_set
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_rule_set FROM PUBLIC;
-- risk_rule_set 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_runtime_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_audit_tenant_policy ON risk_runtime_audit;
CREATE POLICY risk_runtime_audit_tenant_policy ON risk_runtime_audit
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_audit FROM PUBLIC;
-- risk_runtime_audit 是仅追加表：更新与删除在权限层就被拿掉。

-- risk_runtime_capability_health: 不做行级隔离 — platform control metadata has no tenant payload and is guarded by its owning service role

ALTER TABLE risk_runtime_case_resolution ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_case_resolution FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_case_resolution_tenant_policy ON risk_runtime_case_resolution;
CREATE POLICY risk_runtime_case_resolution_tenant_policy ON risk_runtime_case_resolution
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_case_resolution FROM PUBLIC;
-- risk_runtime_case_resolution 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_runtime_decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_decision FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_decision_tenant_policy ON risk_runtime_decision;
CREATE POLICY risk_runtime_decision_tenant_policy ON risk_runtime_decision
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE risk_runtime_list_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_list_entry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_list_entry_tenant_policy ON risk_runtime_list_entry;
CREATE POLICY risk_runtime_list_entry_tenant_policy ON risk_runtime_list_entry
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_list_entry FROM PUBLIC;
-- risk_runtime_list_entry 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_runtime_model_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_model_result FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_model_result_tenant_policy ON risk_runtime_model_result;
CREATE POLICY risk_runtime_model_result_tenant_policy ON risk_runtime_model_result
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_model_result FROM PUBLIC;
-- risk_runtime_model_result 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_runtime_nonce ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_nonce FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_nonce_tenant_policy ON risk_runtime_nonce;
CREATE POLICY risk_runtime_nonce_tenant_policy ON risk_runtime_nonce
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_nonce FROM PUBLIC;
-- risk_runtime_nonce 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_runtime_operation_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_operation_request FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_operation_request_tenant_policy ON risk_runtime_operation_request;
CREATE POLICY risk_runtime_operation_request_tenant_policy ON risk_runtime_operation_request
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE risk_runtime_rule_set ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_rule_set FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_rule_set_tenant_policy ON risk_runtime_rule_set;
CREATE POLICY risk_runtime_rule_set_tenant_policy ON risk_runtime_rule_set
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_rule_set FROM PUBLIC;
-- risk_runtime_rule_set 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_runtime_signal_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_runtime_signal_snapshot FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_runtime_signal_snapshot_tenant_policy ON risk_runtime_signal_snapshot;
CREATE POLICY risk_runtime_signal_snapshot_tenant_policy ON risk_runtime_signal_snapshot
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_runtime_signal_snapshot FROM PUBLIC;
-- risk_runtime_signal_snapshot 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE risk_signal_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_signal_snapshot FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_signal_snapshot_tenant_policy ON risk_signal_snapshot;
CREATE POLICY risk_signal_snapshot_tenant_policy ON risk_signal_snapshot
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON risk_signal_snapshot FROM PUBLIC;
-- risk_signal_snapshot 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE rollout_execution ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_execution FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rollout_execution_tenant_policy ON rollout_execution;
CREATE POLICY rollout_execution_tenant_policy ON rollout_execution
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE statement_file ENABLE ROW LEVEL SECURITY;
ALTER TABLE statement_file FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS statement_file_tenant_policy ON statement_file;
CREATE POLICY statement_file_tenant_policy ON statement_file
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON statement_file FROM PUBLIC;
-- statement_file 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE statement_row ENABLE ROW LEVEL SECURITY;
ALTER TABLE statement_row FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS statement_row_tenant_policy ON statement_row;
CREATE POLICY statement_row_tenant_policy ON statement_row
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON statement_row FROM PUBLIC;
-- statement_row 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE tenant_archive_export_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_export_receipt FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_archive_export_receipt_tenant_policy ON tenant_archive_export_receipt;
CREATE POLICY tenant_archive_export_receipt_tenant_policy ON tenant_archive_export_receipt
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON tenant_archive_export_receipt FROM PUBLIC;
-- tenant_archive_export_receipt 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE tenant_archive_fact ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_archive_fact FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_archive_fact_tenant_policy ON tenant_archive_fact;
CREATE POLICY tenant_archive_fact_tenant_policy ON tenant_archive_fact
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE UPDATE, DELETE ON tenant_archive_fact FROM PUBLIC;
-- tenant_archive_fact 是仅追加表：更新与删除在权限层就被拿掉。

-- tenant_partition_change: 不做行级隔离 — platform control metadata has no tenant payload and is guarded by its owning service role
REVOKE UPDATE, DELETE ON tenant_partition_change FROM PUBLIC;
-- tenant_partition_change 是仅追加表：更新与删除在权限层就被拿掉。

-- 紧急通道
-- 角色 platform_break_glass：需审计事件=True，需二次审批=True，会话上限=60 分钟。
