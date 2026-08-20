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
DROP POLICY IF EXISTS provider_webhook_inbox_tenant_isolation ON provider_webhook_inbox;
CREATE POLICY provider_webhook_inbox_tenant_isolation ON provider_webhook_inbox
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON provider_webhook_inbox FROM PUBLIC;
-- provider_webhook_inbox 是仅追加表：更新与删除在权限层就被拿掉。

ALTER TABLE provider_webhook_raw ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_webhook_raw FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_webhook_raw_tenant_isolation ON provider_webhook_raw;
CREATE POLICY provider_webhook_raw_tenant_isolation ON provider_webhook_raw
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
REVOKE UPDATE, DELETE ON provider_webhook_raw FROM PUBLIC;
-- provider_webhook_raw 是仅追加表：更新与删除在权限层就被拿掉。

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
-- 紧急通道
-- 角色 platform_break_glass：需审计事件=True，需二次审批=True，会话上限=60 分钟。
