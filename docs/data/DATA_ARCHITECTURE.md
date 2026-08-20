<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/data-architecture.json
     Regenerate with: python3 scripts/render-data.py -->

# 数据所有权、分区与租户模型（B13）

本文由 `governance/data-architecture.json` 生成。表的归属由门禁与 `governance/module-registry.json` 强制一致（`DATA_OWNER`）。

## 租户模型

- 模型：`shared_database_shared_schema_with_rls`
- 租户列：`tenant_id`，会话变量 `app.tenant_id`
- 共享库共享表 + 强制行级安全。应用连接使用非 owner 角色，且 owner 角色也必须 FORCE ROW LEVEL SECURITY——否则一次以 owner 身份跑的运维脚本就能跨租户读全表。

**紧急通道**：角色 `platform_break_glass`，必须留审计事件、必须二次审批、会话最长 60 分钟。

跨租户访问必须走单独角色，留审计事件并且四眼复核（NN-11）。没有紧急通道的隔离设计会在第一次故障时被人用 superuser 绕过。

## 归档与分片

- 归档：`object-storage`，格式 parquet，完整性 sha256_manifest。归档必须可校验、可回读。写出去就再也读不回来的归档等于删除。
- 分片：`planned`，键 `tenant_id`。现在不分片，但每张租户表的主键与索引都以 tenant_id 打头，使将来按租户分片成为搬迁而不是重写。

## 表清单

| 表 | 属主模块 | 租户隔离 | 可变性 | 分区 | 热/温/冷（天） | 归档目标 |
| --- | --- | --- | --- | --- | --- | --- |
| `bank_statement` | `reconciliation-service` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/bank_statement` |
| `delivery_attempt` | `webhook-delivery` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 180 / 180 | `object-storage://elmpay-archive/delivery_attempt` |
| `delivery_dead_letter` | `webhook-delivery` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 400 | `object-storage://elmpay-archive/delivery_dead_letter` |
| `delivery_subscription` | `webhook-delivery` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/delivery_subscription` |
| `dispute` | `payment-core` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/dispute` |
| `fee_record` | `ledger-service` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/fee_record` |
| `fx_rate` | `ledger-service` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/fx_rate` |
| `idempotency_key` | `payment-core` | RLS 强制 | mutable | range / `created_at` / monthly | 30 / 30 / 30 | `object-storage://elmpay-archive/idempotency_key` |
| `job_lock` | `worker-scheduler` | RLS 强制 | mutable | 不分区 | 7 / 7 / 7 | `object-storage://elmpay-archive/job_lock` |
| `job_run` | `worker-scheduler` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 180 / 180 | `object-storage://elmpay-archive/job_run` |
| `ledger_account` | `ledger-service` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/ledger_account` |
| `ledger_entry` | `ledger-service` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/ledger_entry` |
| `ledger_transaction` | `ledger-service` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/ledger_transaction` |
| `merchant` | `merchant-config` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/merchant` |
| `outbox_event` | `payment-core` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 90 / 90 | `object-storage://elmpay-archive/outbox_event` |
| `payment_attempt` | `payment-core` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/payment_attempt` |
| `payment_intent` | `payment-core` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/payment_intent` |
| `pricing_rule` | `merchant-config` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/pricing_rule` |
| `project` | `merchant-config` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/project` |
| `provider_account` | `merchant-config` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/provider_account` |
| `provider_capability` | `merchant-config` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/provider_capability` |
| `provider_statement` | `reconciliation-service` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/provider_statement` |
| `provider_webhook_inbox` | `webhook-ingress` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 400 | `object-storage://elmpay-archive/provider_webhook_inbox` |
| `provider_webhook_raw` | `webhook-ingress` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 400 | `object-storage://elmpay-archive/provider_webhook_raw` |
| `recon_exception` | `reconciliation-service` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/recon_exception` |
| `recon_match` | `reconciliation-service` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/recon_match` |
| `recon_run` | `reconciliation-service` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/recon_run` |
| `refund` | `payment-core` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/refund` |
| `risk_case` | `risk-engine` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/risk_case` |
| `risk_decision` | `risk-engine` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/risk_decision` |
| `risk_list_entry` | `risk-engine` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/risk_list_entry` |
| `risk_rule` | `risk-engine` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/risk_rule` |
| `risk_signal` | `risk-engine` | RLS 强制 | append_only | range / `created_at` / monthly | 90 / 400 / 400 | `object-storage://elmpay-archive/risk_signal` |
| `routing_rule` | `merchant-config` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/routing_rule` |
| `scheduled_job` | `worker-scheduler` | RLS 强制 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/scheduled_job` |
| `settlement_instruction` | `ledger-service` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/settlement_instruction` |
| `subscription` | `payment-core` | RLS 强制 | mutable | range / `created_at` / monthly | 90 / 400 / 2555 | `object-storage://elmpay-archive/subscription` |
| `tenant` | `merchant-config` | 不适用 | mutable | 不分区 | 2555 / 2555 / 2555 | `object-storage://elmpay-archive/tenant` |

### 仅追加表（14 张）

这些表记录的是**发生过什么**，不是**现在是什么**。它们可以被插入和读取，不能被更新或删除——生成的 DDL 在权限层直接拿掉 UPDATE/DELETE。

`bank_statement`、`delivery_attempt`、`delivery_dead_letter`、`fee_record`、`job_run`、`ledger_entry`、`ledger_transaction`、`outbox_event`、`provider_statement`、`provider_webhook_inbox`、`provider_webhook_raw`、`recon_match`、`risk_decision`、`risk_signal`

### 含个人数据的表（3 张）

| 表 | 个人数据列 | 删除策略 |
| --- | --- | --- |
| `dispute` | `cardholder_reference` | `crypto_shred` |
| `merchant` | `contact_email`、`contact_phone` | `crypto_shred` |
| `risk_case` | `reviewer_note` | `crypto_shred` |

共 38 张表，其中 37 张受租户隔离，14 张仅追加。
