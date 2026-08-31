-- GENERATED FILE — do not edit by hand.
-- Source of truth: governance/data-architecture.json
-- Regenerate with: python3 scripts/render-data.py

-- 分区与归档：按月 RANGE 分区，归档是 DETACH 而不是 DELETE。

-- bank_statement: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE bank_statement SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE bank_statement DETACH PARTITION bank_statement_<period>; 再导出到 object-storage://elmpay-archive/bank_statement

-- delivery_attempt: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 180 天 / 冷 180 天
ALTER TABLE delivery_attempt SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE delivery_attempt DETACH PARTITION delivery_attempt_<period>; 再导出到 object-storage://elmpay-archive/delivery_attempt

-- delivery_dead_letter: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 400 天
ALTER TABLE delivery_dead_letter SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE delivery_dead_letter DETACH PARTITION delivery_dead_letter_<period>; 再导出到 object-storage://elmpay-archive/delivery_dead_letter

-- delivery_subscription: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/delivery_subscription

-- dispute: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE dispute SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE dispute DETACH PARTITION dispute_<period>; 再导出到 object-storage://elmpay-archive/dispute

-- fee_record: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE fee_record SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE fee_record DETACH PARTITION fee_record_<period>; 再导出到 object-storage://elmpay-archive/fee_record

-- fx_rate: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/fx_rate

-- idempotency_key: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 30 天 / 温 30 天 / 冷 30 天
ALTER TABLE idempotency_key SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE idempotency_key DETACH PARTITION idempotency_key_<period>; 再导出到 object-storage://elmpay-archive/idempotency_key

-- job_lock: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 7 天，归档至 object-storage://elmpay-archive/job_lock

-- job_run: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 180 天 / 冷 180 天
ALTER TABLE job_run SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE job_run DETACH PARTITION job_run_<period>; 再导出到 object-storage://elmpay-archive/job_run

-- ledger_account: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE ledger_account SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE ledger_account DETACH PARTITION ledger_account_<period>; 再导出到 object-storage://elmpay-archive/ledger_account

-- ledger_entry: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE ledger_entry SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE ledger_entry DETACH PARTITION ledger_entry_<period>; 再导出到 object-storage://elmpay-archive/ledger_entry

-- ledger_transaction: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE ledger_transaction SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE ledger_transaction DETACH PARTITION ledger_transaction_<period>; 再导出到 object-storage://elmpay-archive/ledger_transaction

-- merchant: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/merchant

-- outbox_event: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 90 天 / 冷 90 天
ALTER TABLE outbox_event SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE outbox_event DETACH PARTITION outbox_event_<period>; 再导出到 object-storage://elmpay-archive/outbox_event

-- payment_attempt: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE payment_attempt SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE payment_attempt DETACH PARTITION payment_attempt_<period>; 再导出到 object-storage://elmpay-archive/payment_attempt

-- payment_intent: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE payment_intent SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE payment_intent DETACH PARTITION payment_intent_<period>; 再导出到 object-storage://elmpay-archive/payment_intent

-- pricing_rule: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/pricing_rule

-- project: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/project

-- provider_account: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/provider_account

-- provider_capability: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/provider_capability

-- provider_effect_application: 不分区 — immutable provider-event application facts are compact and keyed by tenant/provider event identity
--   保留 2555 天，归档至 object-storage://elmpay-archive/provider_effect_application

-- provider_effect_expectation: 不分区 — immutable capture expectation is one compact fact per payment attempt
--   保留 2555 天，归档至 object-storage://elmpay-archive/provider_effect_expectation

-- provider_effect_target_clock: 不分区 — one monotonic provider ordering fence per bound payment or refund
--   保留 2555 天，归档至 object-storage://elmpay-archive/provider_effect_target_clock

-- provider_statement: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE provider_statement SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE provider_statement DETACH PARTITION provider_statement_<period>; 再导出到 object-storage://elmpay-archive/provider_statement

-- provider_webhook_inbox: 不分区 — lease/fencing state is updated in place; partitioning requires a later online migration
--   保留 400 天，归档至 object-storage://elmpay-archive/provider_webhook_inbox

-- provider_webhook_effect_commit: 不分区 — compact append-only idempotency marker keyed by tenant and inbox id
--   保留 400 天，归档至 object-storage://elmpay-archive/provider_webhook_effect_commit

-- recon_exception: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE recon_exception SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE recon_exception DETACH PARTITION recon_exception_<period>; 再导出到 object-storage://elmpay-archive/recon_exception

-- recon_match: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE recon_match SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE recon_match DETACH PARTITION recon_match_<period>; 再导出到 object-storage://elmpay-archive/recon_match

-- recon_run: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE recon_run SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE recon_run DETACH PARTITION recon_run_<period>; 再导出到 object-storage://elmpay-archive/recon_run

-- refund: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE refund SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE refund DETACH PARTITION refund_<period>; 再导出到 object-storage://elmpay-archive/refund

-- risk_case: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE risk_case SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE risk_case DETACH PARTITION risk_case_<period>; 再导出到 object-storage://elmpay-archive/risk_case

-- risk_decision: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE risk_decision SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE risk_decision DETACH PARTITION risk_decision_<period>; 再导出到 object-storage://elmpay-archive/risk_decision

-- risk_list_entry: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_list_entry

-- risk_rule: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_rule

-- risk_signal: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 400 天
ALTER TABLE risk_signal SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE risk_signal DETACH PARTITION risk_signal_<period>; 再导出到 object-storage://elmpay-archive/risk_signal

-- routing_rule: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/routing_rule

-- scheduled_job: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/scheduled_job

-- settlement_instruction: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE settlement_instruction SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE settlement_instruction DETACH PARTITION settlement_instruction_<period>; 再导出到 object-storage://elmpay-archive/settlement_instruction

-- subscription: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE subscription SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE subscription DETACH PARTITION subscription_<period>; 再导出到 object-storage://elmpay-archive/subscription

-- tenant: 不分区 — 参考数据体量小、被高频读取，分区只会增加计划开销
--   保留 2555 天，归档至 object-storage://elmpay-archive/tenant

-- admin_access_audit: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_access_audit

-- admin_action_diagnostic_audit: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_action_diagnostic_audit

-- admin_action_dispatch: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_action_dispatch

-- admin_action_effect_receipt: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_action_effect_receipt

-- admin_approval: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_approval

-- admin_approval_audit: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_approval_audit

-- admin_diagnostic_snapshot: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_diagnostic_snapshot

-- admin_dispatch_signal: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_dispatch_signal

-- admin_domain_command: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_domain_command

-- admin_domain_command_signal: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_domain_command_signal

-- admin_dpop_nonce: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_dpop_nonce

-- admin_dpop_replay: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_dpop_replay

-- admin_rollout_stage_approval: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/admin_rollout_stage_approval

-- consumer_event_inbox: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/consumer_event_inbox

-- data_table_ownership: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/data_table_ownership

-- event_aggregate_revision: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/event_aggregate_revision

-- financial_admin_audit: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/financial_admin_audit

-- financial_export: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/financial_export

-- financial_runtime_job: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/financial_runtime_job

-- ledger_event_revision_guard: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/ledger_event_revision_guard

-- ledger_posting_account_mapping: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/ledger_posting_account_mapping

-- ledger_posting_policy: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/ledger_posting_policy

-- recon_exception_action: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/recon_exception_action

-- recon_exception_current: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/recon_exception_current

-- recon_exception_origin: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/recon_exception_origin

-- reconciliation_fact_snapshot: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/reconciliation_fact_snapshot

-- reconciliation_fact_snapshot_member: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/reconciliation_fact_snapshot_member

-- reconciliation_schedule_cursor: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/reconciliation_schedule_cursor

-- risk_audit: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_audit

-- risk_operation: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_operation

-- risk_outbox: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_outbox

-- risk_rule_set: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_rule_set

-- risk_runtime_audit: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_audit

-- risk_runtime_capability_health: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_capability_health

-- risk_runtime_case_resolution: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_case_resolution

-- risk_runtime_decision: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_decision

-- risk_runtime_list_entry: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_list_entry

-- risk_runtime_model_result: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_model_result

-- risk_runtime_nonce: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_nonce

-- risk_runtime_operation_request: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_operation_request

-- risk_runtime_rule_set: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_rule_set

-- risk_runtime_signal_snapshot: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_runtime_signal_snapshot

-- risk_signal_snapshot: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/risk_signal_snapshot

-- rollout_execution: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/rollout_execution

-- statement_file: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/statement_file

-- statement_row: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/statement_row

-- tenant_archive_export_receipt: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/tenant_archive_export_receipt

-- tenant_archive_fact: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/tenant_archive_fact

-- tenant_partition_change: 不分区 — compact operational control state is retained in place; range partitioning is not required for this bounded relation
--   保留 2555 天，归档至 object-storage://elmpay-archive/tenant_partition_change
