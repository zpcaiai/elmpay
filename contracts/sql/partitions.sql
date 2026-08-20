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

-- provider_statement: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 2555 天
ALTER TABLE provider_statement SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE provider_statement DETACH PARTITION provider_statement_<period>; 再导出到 object-storage://elmpay-archive/provider_statement

-- provider_webhook_inbox: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 400 天
ALTER TABLE provider_webhook_inbox SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE provider_webhook_inbox DETACH PARTITION provider_webhook_inbox_<period>; 再导出到 object-storage://elmpay-archive/provider_webhook_inbox

-- provider_webhook_raw: range 分区，键 created_at，间隔 monthly
--   支付数据按时间写入、按时间归档；按月分区让归档变成 DETACH 而不是 DELETE
--   热 90 天 / 温 400 天 / 冷 400 天
ALTER TABLE provider_webhook_raw SET (autovacuum_vacuum_scale_factor = 0.02);
-- PARTITION BY RANGE (created_at) — 分区表创建见迁移脚本；
-- 归档：ALTER TABLE provider_webhook_raw DETACH PARTITION provider_webhook_raw_<period>; 再导出到 object-storage://elmpay-archive/provider_webhook_raw

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
