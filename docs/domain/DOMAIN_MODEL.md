<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/domain-model.json
     Regenerate with: python3 scripts/render-docs.py -->

# 支付领域模型（B08）

实体 14 个 · 字段 133 个 · 不变量 43 条。

本模型是**语言中立的规范定义**；PostgreSQL DDL 由它生成，
Java 类型与 API 契约在 B11 生成。禁止在生成物中手工新增字段。

| 实体 | 所属模块 | 表 | 租户隔离 | 用途 |
| --- | --- | --- | --- | --- |
| Tenant | `merchant-config` | `tenant` | 否 | 平台的顶层隔离单元；一个客户组织一个租户。 |
| Project | `merchant-config` | `project` | 是 | 业务项目：接入平台的一个业务系统，拥有自己的业务订单。 |
| Merchant | `merchant-config` | `merchant` | 是 | 商户：结算主体，与渠道商户号绑定。 |
| ProviderAccount | `merchant-config` | `provider_account` | 是 | 商户在某渠道下的账户与凭证引用。 |
| PaymentIntent | `payment-core` | `payment_intent` | 是 | 一次付款意图；平台的支付事实入口。 |
| PaymentAttempt | `payment-core` | `payment_attempt` | 是 | 一次面向渠道的支付尝试。 |
| Refund | `payment-core` | `refund` | 是 | 针对已捕获金额的退款。 |
| Dispute | `payment-core` | `dispute` | 是 | 争议或拒付：付款人通过渠道发起的资金争议，含举证时限与裁定结果。 |
| Subscription | `payment-core` | `subscription` | 是 | 周期计费订阅：依据 Mandate 或 PSP 令牌引用按周期扣款的计费关系。 |
| LedgerAccount | `ledger-service` | `ledger_account` | 是 | 复式账本科目：按租户与币种独立的记账科目。 |
| LedgerTransaction | `ledger-service` | `ledger_transaction` | 是 | 一组必须借贷平衡的分录。 |
| LedgerEntry | `ledger-service` | `ledger_entry` | 是 | 单条借或贷分录：账本中最小的不可变记账单位。 |
| ReconciliationRun | `reconciliation-service` | `recon_run` | 是 | 一次对账运行：针对某渠道某业务日的账单摄取与逐笔匹配过程。 |
| ReconciliationException | `reconciliation-service` | `recon_exception` | 是 | 对账差异：三方对账中未匹配或金额、状态不一致的条目。 |

## Tenant　`tenant`

平台的顶层隔离单元；一个客户组织一个租户。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  | 租户内部标识，全局唯一 |
| `code` | `string` | 非空 |  | 人类可读租户代码，创建后不可变 |
| `display_name` | `string` | 非空 |  | 展示名 |
| `status` | `enum` | 非空 | active suspended closed | 租户生命周期状态 |
| `data_residency` | `string` | 非空 |  | ISO-3166 alpha-2 数据驻留地 |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

不变量：
- code 创建后不可变
- suspended 租户不得创建新的 PaymentIntent
- closed 租户只允许只读查询与对账

## Project　`project`

业务项目：接入平台的一个业务系统，拥有自己的业务订单。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `code` | `string` | 非空 |  | 租户内唯一的项目代码 |
| `display_name` | `string` | 非空 |  |  |
| `callback_domains` | `json` | 非空 |  | 登记的回调域名白名单；不在其中的 notify_url 一律拒绝 |
| `status` | `enum` | 非空 | active suspended |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

不变量：
- (tenant_id, code) 唯一
- callback_domains 非空且必须是已登记域名
- 项目不得存储商品或库存信息

## Merchant　`merchant`

商户：结算主体，与渠道商户号绑定。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `legal_name` | `string` | 非空 |  | 法定名称；KYB 元数据在 B25 扩展 |
| `settlement_mode` | `enum` | 非空 | direct_to_merchant | 仅允许持牌机构直达商户结算；平台不持有资金 |
| `status` | `enum` | 非空 | onboarding active suspended terminated |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

不变量：
- settlement_mode 只能是 direct_to_merchant（NN-13）
- terminated 商户不得发起新支付

## ProviderAccount　`provider_account`

商户在某渠道下的账户与凭证引用。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `merchant_id` | `reference` | 非空 | → Merchant |  |
| `provider` | `enum` | 非空 | wechat alipay stripe paypal apple_pay |  |
| `provider_merchant_id` | `string` | 非空 |  | 渠道侧商户号 |
| `credential_ref` | `string` | 非空 |  | kms:// 或 vault:// 引用；禁止明文 |
| `environment` | `enum` | 非空 | sandbox production |  |
| `status` | `enum` | 非空 | pending active disabled |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

不变量：
- credential_ref 必须以 kms:// 或 vault:// 开头（NN-07）
- (tenant_id, merchant_id, provider, environment) 唯一
- sandbox 与 production 凭证不得共用记录

## PaymentIntent　`payment_intent`

一次付款意图；平台的支付事实入口。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `project_id` | `reference` | 非空 | → Project |  |
| `merchant_id` | `reference` | 非空 | → Merchant |  |
| `external_reference` | `string` | 非空 |  | 业务项目的业务订单号；与 project_id 组成唯一键 |
| `amount_minor` | `money_minor` | 非空 |  | 最小货币单位整数，禁止浮点（NN-05） |
| `currency` | `currency` | 非空 |  |  |
| `captured_amount_minor` | `money_minor` | 非空 |  | 已捕获金额 |
| `refunded_amount_minor` | `money_minor` | 非空 |  | 已退款金额 |
| `state` | `enum` | 非空 | created requires_action authorized captured failed canceled expired |  |
| `idempotency_key` | `string` | 非空 |  | 创建幂等键；唯一约束 |
| `client_secret_ref` | `string` | 可空 |  | 面向客户端的短期引用，不含凭证 |
| `expires_at` | `timestamp` | 可空 |  |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

状态：`created`、`requires_action`、`authorized`、`captured`、`failed`、`canceled`、`expired`

不变量：
- (project_id, external_reference) 唯一（NN-01）
- amount_minor > 0
- captured_amount_minor <= amount_minor
- refunded_amount_minor <= captured_amount_minor
- 状态只允许声明的单向或补偿式转换
- 不得包含商品、库存或履约字段（NN-01）
- 成功状态只能由验签渠道事件或服务端查询写入（NN-03）

## PaymentAttempt　`payment_attempt`

一次面向渠道的支付尝试。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `payment_intent_id` | `reference` | 非空 | → PaymentIntent |  |
| `provider_account_id` | `reference` | 非空 | → ProviderAccount |  |
| `provider` | `enum` | 非空 | wechat alipay stripe paypal apple_pay |  |
| `provider_transaction_id` | `string` | 可空 |  | 渠道交易号 |
| `state` | `enum` | 非空 | initiated pending succeeded failed unknown |  |
| `failure_category` | `enum` | 可空 | network timeout declined risk_blocked config provider_error |  |
| `request_digest` | `string` | 非空 |  | 请求体摘要，用于幂等与审计；不存原文凭证 |
| `started_at` | `timestamp` | 非空 |  |  |
| `settled_at` | `timestamp` | 可空 |  |  |

状态：`initiated`、`pending`、`succeeded`、`failed`、`unknown`

不变量：
- unknown 状态必须触发主动查询直到收敛（NN-03）
- (provider, provider_transaction_id) 在非空时唯一
- request_digest 不得包含凭证或卡数据（NN-14）

## Refund　`refund`

针对已捕获金额的退款。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `payment_intent_id` | `reference` | 非空 | → PaymentIntent |  |
| `amount_minor` | `money_minor` | 非空 |  |  |
| `currency` | `currency` | 非空 |  |  |
| `reason` | `enum` | 非空 | requested_by_customer duplicate fraudulent dispute other |  |
| `state` | `enum` | 非空 | requested approved processing succeeded failed canceled |  |
| `idempotency_key` | `string` | 非空 |  |  |
| `approved_by` | `string` | 可空 |  | 四眼复核的审批人；与发起人不同 |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

状态：`requested`、`approved`、`processing`、`succeeded`、`failed`、`canceled`

不变量：
- sum(refund.amount_minor) <= payment_intent.captured_amount_minor
- amount_minor > 0
- approved_by 必须不同于发起人（NN-11）
- idempotency_key 唯一

## Dispute　`dispute`

争议或拒付：付款人通过渠道发起的资金争议，含举证时限与裁定结果。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `payment_intent_id` | `reference` | 非空 | → PaymentIntent |  |
| `provider_dispute_id` | `string` | 非空 |  |  |
| `amount_minor` | `money_minor` | 非空 |  |  |
| `currency` | `currency` | 非空 |  |  |
| `state` | `enum` | 非空 | opened evidence_required under_review won lost withdrawn |  |
| `evidence_due_at` | `timestamp` | 可空 |  |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

状态：`opened`、`evidence_required`、`under_review`、`won`、`lost`、`withdrawn`

不变量：
- provider_dispute_id 唯一
- 状态变化必须产生账本分录

## Subscription　`subscription`

周期计费订阅：依据 Mandate 或 PSP 令牌引用按周期扣款的计费关系。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `project_id` | `reference` | 非空 | → Project |  |
| `merchant_id` | `reference` | 非空 | → Merchant |  |
| `mandate_ref` | `string` | 非空 |  | Mandate 或 PSP 令牌引用；不存可复用明文令牌（NN-02） |
| `amount_minor` | `money_minor` | 非空 |  |  |
| `currency` | `currency` | 非空 |  |  |
| `interval` | `enum` | 非空 | day week month year |  |
| `interval_count` | `int32` | 非空 |  |  |
| `state` | `enum` | 非空 | trialing active past_due canceled ended |  |
| `next_billing_at` | `timestamp` | 可空 |  |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

状态：`trialing`、`active`、`past_due`、`canceled`、`ended`

不变量：
- interval_count > 0
- mandate_ref 不得是明文支付令牌（NN-02）
- canceled/ended 订阅不得再产生扣款

## LedgerAccount　`ledger_account`

复式账本科目：按租户与币种独立的记账科目。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `code` | `string` | 非空 |  | 科目代码 |
| `kind` | `enum` | 非空 | asset liability revenue expense clearing |  |
| `currency` | `currency` | 非空 |  |  |
| `created_at` | `timestamp` | 非空 |  |  |

不变量：
- (tenant_id, code, currency) 唯一
- 平台不得存在自有资金池类型科目（NN-13）

## LedgerTransaction　`ledger_transaction`

一组必须借贷平衡的分录。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `source_kind` | `enum` | 非空 | payment refund fee fx dispute adjustment settlement |  |
| `source_id` | `string` | 非空 |  | 来源事实的标识，用于唯一性与追溯 |
| `posted_at` | `timestamp` | 非空 |  |  |
| `reason` | `string` | 可空 |  | 人工调整必填理由 |
| `approved_by` | `string` | 可空 |  | 人工调整必填复核人（NN-11） |

不变量：
- (tenant_id, source_kind, source_id) 唯一，防止重复过账（NN-04）
- 分录一经写入禁止 UPDATE/DELETE（NN-06）
- adjustment 必须同时具备 reason 与 approved_by

## LedgerEntry　`ledger_entry`

单条借或贷分录：账本中最小的不可变记账单位。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `transaction_id` | `reference` | 非空 | → LedgerTransaction |  |
| `account_id` | `reference` | 非空 | → LedgerAccount |  |
| `direction` | `enum` | 非空 | debit credit |  |
| `amount_minor` | `money_minor` | 非空 |  |  |
| `currency` | `currency` | 非空 |  |  |
| `posted_at` | `timestamp` | 非空 |  |  |

不变量：
- amount_minor > 0
- 同一 transaction 内 sum(debit) == sum(credit)（按币种）
- 分录不可变（NN-06）
- currency 必须等于 account.currency

## ReconciliationRun　`recon_run`

一次对账运行：针对某渠道某业务日的账单摄取与逐笔匹配过程。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `business_date` | `string` | 非空 |  | 对账业务日 YYYY-MM-DD |
| `provider` | `enum` | 非空 | wechat alipay stripe paypal apple_pay |  |
| `source_file_digest` | `string` | 非空 |  | 账单文件 SHA-256，用于幂等摄取（NN-04） |
| `state` | `enum` | 非空 | ingesting matching completed failed |  |
| `started_at` | `timestamp` | 非空 |  |  |
| `completed_at` | `timestamp` | 可空 |  |  |

状态：`ingesting`、`matching`、`completed`、`failed`

不变量：
- (tenant_id, provider, business_date, source_file_digest) 唯一
- 同一文件重复摄取不得产生重复记录

## ReconciliationException　`recon_exception`

对账差异：三方对账中未匹配或金额、状态不一致的条目。

| 字段 | 类型 | 可空 | 取值/引用 | 语义 |
| --- | --- | --- | --- | --- |
| `id` | `uuid` | 非空 |  |  |
| `tenant_id` | `reference` | 非空 | → Tenant |  |
| `run_id` | `reference` | 非空 | → ReconciliationRun |  |
| `category` | `enum` | 非空 | missing_in_platform missing_in_provider amount_mismatch status_mismatch duplicate fee_mismatch timing |  |
| `payment_intent_id` | `reference` | 可空 | → PaymentIntent |  |
| `amount_minor` | `money_minor` | 可空 |  |  |
| `currency` | `currency` | 可空 |  |  |
| `state` | `enum` | 非空 | open investigating resolved written_off |  |
| `resolution_reason` | `string` | 可空 |  |  |
| `approved_by` | `string` | 可空 |  |  |
| `created_at` | `timestamp` | 非空 |  |  |
| `updated_at` | `timestamp` | 非空 |  |  |

状态：`open`、`investigating`、`resolved`、`written_off`

不变量：
- 每条差异必须有分类，不允许 unknown
- written_off 必须具备 resolution_reason 与 approved_by（NN-11）
