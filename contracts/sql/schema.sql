-- GENERATED FILE — do not edit by hand.
-- Source of truth: governance/domain-model.json
-- Regenerate with: python3 scripts/render-domain.py

-- All monetary columns are BIGINT minor units (NN-05).
-- Ledger entries are append-only; revocation of UPDATE/DELETE is granted in B72.

-- Tenant: 平台的顶层隔离单元；一个客户组织一个租户。
CREATE TABLE IF NOT EXISTS tenant (
    id uuid NOT NULL,
    code text NOT NULL,
    display_name text NOT NULL,
    status text NOT NULL,
    data_residency text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT tenant_pk PRIMARY KEY (id),
    CONSTRAINT tenant_status_enum CHECK (status IN ('active', 'suspended', 'closed'))
);

-- Project: 业务项目：接入平台的一个业务系统，拥有自己的业务订单。
CREATE TABLE IF NOT EXISTS project (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    code text NOT NULL,
    display_name text NOT NULL,
    callback_domains jsonb NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT project_pk PRIMARY KEY (id),
    CONSTRAINT project_tenant_id_fk FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT project_status_enum CHECK (status IN ('active', 'suspended'))
);
CREATE INDEX IF NOT EXISTS project_tenant_idx ON project (tenant_id);
ALTER TABLE project ENABLE ROW LEVEL SECURITY;

-- Merchant: 商户：结算主体，与渠道商户号绑定。
CREATE TABLE IF NOT EXISTS merchant (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    legal_name text NOT NULL,
    settlement_mode text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT merchant_pk PRIMARY KEY (id),
    CONSTRAINT merchant_tenant_id_fk FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT merchant_settlement_mode_enum CHECK (settlement_mode IN ('direct_to_merchant')),
    CONSTRAINT merchant_status_enum CHECK (status IN ('onboarding', 'active', 'suspended', 'terminated'))
);
CREATE INDEX IF NOT EXISTS merchant_tenant_idx ON merchant (tenant_id);
ALTER TABLE merchant ENABLE ROW LEVEL SECURITY;

-- ProviderAccount: 商户在某渠道下的账户与凭证引用。
CREATE TABLE IF NOT EXISTS provider_account (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    provider text NOT NULL,
    provider_merchant_id text NOT NULL,
    credential_ref text NOT NULL,
    environment text NOT NULL,
    status text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT provider_account_pk PRIMARY KEY (id),
    CONSTRAINT provider_account_tenant_id_fk FOREIGN KEY (tenant_id) REFERENCES tenant (id),
    CONSTRAINT provider_account_merchant_id_fk FOREIGN KEY (merchant_id) REFERENCES merchant (id),
    CONSTRAINT provider_account_provider_enum CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal', 'apple_pay')),
    CONSTRAINT provider_account_environment_enum CHECK (environment IN ('sandbox', 'production')),
    CONSTRAINT provider_account_status_enum CHECK (status IN ('pending', 'active', 'disabled'))
);
CREATE INDEX IF NOT EXISTS provider_account_tenant_idx ON provider_account (tenant_id);
ALTER TABLE provider_account ENABLE ROW LEVEL SECURITY;

-- PaymentIntent: 一次付款意图；平台的支付事实入口。
CREATE TABLE IF NOT EXISTS payment_intent (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    external_reference text NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    captured_amount_minor bigint NOT NULL,
    refunded_amount_minor bigint NOT NULL,
    state text NOT NULL,
    idempotency_key text NOT NULL,
    client_secret_ref text,
    expires_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT payment_intent_pk PRIMARY KEY (id),
    CONSTRAINT payment_intent_amount_minor_positive CHECK (amount_minor > 0),
    CONSTRAINT payment_intent_currency_iso CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT payment_intent_captured_amount_minor_positive CHECK (captured_amount_minor >= 0),
    CONSTRAINT payment_intent_refunded_amount_minor_positive CHECK (refunded_amount_minor >= 0),
    CONSTRAINT payment_intent_state_enum CHECK (state IN ('created', 'requires_action', 'authorized', 'captured', 'failed', 'canceled', 'expired'))
);
-- payment_intent.tenant_id -> tenant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
-- payment_intent.project_id -> project: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
-- payment_intent.merchant_id -> merchant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS payment_intent_tenant_idx ON payment_intent (tenant_id);
ALTER TABLE payment_intent ENABLE ROW LEVEL SECURITY;

-- PaymentAttempt: 一次面向渠道的支付尝试。
CREATE TABLE IF NOT EXISTS payment_attempt (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    provider_account_id uuid NOT NULL,
    provider text NOT NULL,
    provider_transaction_id text,
    state text NOT NULL,
    failure_category text,
    request_digest text NOT NULL,
    started_at timestamptz NOT NULL,
    settled_at timestamptz,
    CONSTRAINT payment_attempt_pk PRIMARY KEY (id),
    CONSTRAINT payment_attempt_payment_intent_id_fk FOREIGN KEY (payment_intent_id) REFERENCES payment_intent (id),
    CONSTRAINT payment_attempt_provider_enum CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal', 'apple_pay')),
    CONSTRAINT payment_attempt_state_enum CHECK (state IN ('initiated', 'pending', 'succeeded', 'failed', 'unknown')),
    CONSTRAINT payment_attempt_failure_category_enum CHECK (failure_category IN ('network', 'timeout', 'declined', 'risk_blocked', 'config', 'provider_error'))
);
-- payment_attempt.tenant_id -> tenant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
-- payment_attempt.provider_account_id -> provider_account: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS payment_attempt_tenant_idx ON payment_attempt (tenant_id);
ALTER TABLE payment_attempt ENABLE ROW LEVEL SECURITY;

-- Refund: 针对已捕获金额的退款。
CREATE TABLE IF NOT EXISTS refund (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    reason text NOT NULL,
    state text NOT NULL,
    idempotency_key text NOT NULL,
    approved_by text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT refund_pk PRIMARY KEY (id),
    CONSTRAINT refund_payment_intent_id_fk FOREIGN KEY (payment_intent_id) REFERENCES payment_intent (id),
    CONSTRAINT refund_amount_minor_positive CHECK (amount_minor > 0),
    CONSTRAINT refund_currency_iso CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT refund_reason_enum CHECK (reason IN ('requested_by_customer', 'duplicate', 'fraudulent', 'dispute', 'other')),
    CONSTRAINT refund_state_enum CHECK (state IN ('requested', 'approved', 'processing', 'succeeded', 'failed', 'canceled'))
);
-- refund.tenant_id -> tenant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS refund_tenant_idx ON refund (tenant_id);
ALTER TABLE refund ENABLE ROW LEVEL SECURITY;

-- Dispute: 争议或拒付：付款人通过渠道发起的资金争议，含举证时限与裁定结果。
CREATE TABLE IF NOT EXISTS dispute (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    payment_intent_id uuid NOT NULL,
    provider_dispute_id text NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    state text NOT NULL,
    evidence_due_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT dispute_pk PRIMARY KEY (id),
    CONSTRAINT dispute_payment_intent_id_fk FOREIGN KEY (payment_intent_id) REFERENCES payment_intent (id),
    CONSTRAINT dispute_amount_minor_positive CHECK (amount_minor > 0),
    CONSTRAINT dispute_currency_iso CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT dispute_state_enum CHECK (state IN ('opened', 'evidence_required', 'under_review', 'won', 'lost', 'withdrawn'))
);
-- dispute.tenant_id -> tenant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS dispute_tenant_idx ON dispute (tenant_id);
ALTER TABLE dispute ENABLE ROW LEVEL SECURITY;

-- Subscription: 周期计费订阅：依据 Mandate 或 PSP 令牌引用按周期扣款的计费关系。
CREATE TABLE IF NOT EXISTS subscription (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    merchant_id uuid NOT NULL,
    mandate_ref text NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    interval text NOT NULL,
    interval_count integer NOT NULL,
    state text NOT NULL,
    next_billing_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT subscription_pk PRIMARY KEY (id),
    CONSTRAINT subscription_amount_minor_positive CHECK (amount_minor > 0),
    CONSTRAINT subscription_currency_iso CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT subscription_interval_enum CHECK (interval IN ('day', 'week', 'month', 'year')),
    CONSTRAINT subscription_state_enum CHECK (state IN ('trialing', 'active', 'past_due', 'canceled', 'ended'))
);
-- subscription.tenant_id -> tenant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
-- subscription.project_id -> project: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
-- subscription.merchant_id -> merchant: 跨模块引用（payment-core -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS subscription_tenant_idx ON subscription (tenant_id);
ALTER TABLE subscription ENABLE ROW LEVEL SECURITY;

-- LedgerAccount: 复式账本科目：按租户与币种独立的记账科目。
CREATE TABLE IF NOT EXISTS ledger_account (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    code text NOT NULL,
    kind text NOT NULL,
    currency char(3) NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT ledger_account_pk PRIMARY KEY (id),
    CONSTRAINT ledger_account_kind_enum CHECK (kind IN ('asset', 'liability', 'revenue', 'expense', 'clearing')),
    CONSTRAINT ledger_account_currency_iso CHECK (currency ~ '^[A-Z]{3}$')
);
-- ledger_account.tenant_id -> tenant: 跨模块引用（ledger-service -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS ledger_account_tenant_idx ON ledger_account (tenant_id);
ALTER TABLE ledger_account ENABLE ROW LEVEL SECURITY;

-- LedgerTransaction: 一组必须借贷平衡的分录。
CREATE TABLE IF NOT EXISTS ledger_transaction (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    source_kind text NOT NULL,
    source_id text NOT NULL,
    posted_at timestamptz NOT NULL,
    reason text,
    approved_by text,
    CONSTRAINT ledger_transaction_pk PRIMARY KEY (id),
    CONSTRAINT ledger_transaction_source_kind_enum CHECK (source_kind IN ('payment', 'refund', 'fee', 'fx', 'dispute', 'adjustment', 'settlement'))
);
-- ledger_transaction.tenant_id -> tenant: 跨模块引用（ledger-service -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS ledger_transaction_tenant_idx ON ledger_transaction (tenant_id);
ALTER TABLE ledger_transaction ENABLE ROW LEVEL SECURITY;

-- LedgerEntry: 单条借或贷分录：账本中最小的不可变记账单位。
CREATE TABLE IF NOT EXISTS ledger_entry (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    account_id uuid NOT NULL,
    direction text NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    posted_at timestamptz NOT NULL,
    CONSTRAINT ledger_entry_pk PRIMARY KEY (id),
    CONSTRAINT ledger_entry_transaction_id_fk FOREIGN KEY (transaction_id) REFERENCES ledger_transaction (id),
    CONSTRAINT ledger_entry_account_id_fk FOREIGN KEY (account_id) REFERENCES ledger_account (id),
    CONSTRAINT ledger_entry_direction_enum CHECK (direction IN ('debit', 'credit')),
    CONSTRAINT ledger_entry_amount_minor_positive CHECK (amount_minor > 0),
    CONSTRAINT ledger_entry_currency_iso CHECK (currency ~ '^[A-Z]{3}$')
);
-- ledger_entry.tenant_id -> tenant: 跨模块引用（ledger-service -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS ledger_entry_tenant_idx ON ledger_entry (tenant_id);
ALTER TABLE ledger_entry ENABLE ROW LEVEL SECURITY;

-- ReconciliationRun: 一次对账运行：针对某渠道某业务日的账单摄取与逐笔匹配过程。
CREATE TABLE IF NOT EXISTS recon_run (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    business_date text NOT NULL,
    provider text NOT NULL,
    source_file_digest text NOT NULL,
    state text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    CONSTRAINT recon_run_pk PRIMARY KEY (id),
    CONSTRAINT recon_run_provider_enum CHECK (provider IN ('wechat', 'alipay', 'stripe', 'paypal', 'apple_pay')),
    CONSTRAINT recon_run_state_enum CHECK (state IN ('ingesting', 'matching', 'completed', 'failed'))
);
-- recon_run.tenant_id -> tenant: 跨模块引用（reconciliation-service -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
CREATE INDEX IF NOT EXISTS recon_run_tenant_idx ON recon_run (tenant_id);
ALTER TABLE recon_run ENABLE ROW LEVEL SECURITY;

-- ReconciliationException: 对账差异：三方对账中未匹配或金额、状态不一致的条目。
CREATE TABLE IF NOT EXISTS recon_exception (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    category text NOT NULL,
    payment_intent_id uuid,
    amount_minor bigint,
    currency char(3),
    state text NOT NULL,
    resolution_reason text,
    approved_by text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT recon_exception_pk PRIMARY KEY (id),
    CONSTRAINT recon_exception_run_id_fk FOREIGN KEY (run_id) REFERENCES recon_run (id),
    CONSTRAINT recon_exception_category_enum CHECK (category IN ('missing_in_platform', 'missing_in_provider', 'amount_mismatch', 'status_mismatch', 'duplicate', 'fee_mismatch', 'timing')),
    CONSTRAINT recon_exception_amount_minor_positive CHECK (amount_minor IS NULL OR amount_minor > 0),
    CONSTRAINT recon_exception_currency_iso CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
    CONSTRAINT recon_exception_state_enum CHECK (state IN ('open', 'investigating', 'resolved', 'written_off'))
);
-- recon_exception.tenant_id -> tenant: 跨模块引用（reconciliation-service -> merchant-config），不建数据库外键；由 merchant-config 负责校验存在性。
-- recon_exception.payment_intent_id -> payment_intent: 跨模块引用（reconciliation-service -> payment-core），不建数据库外键；由 payment-core 负责校验存在性。
CREATE INDEX IF NOT EXISTS recon_exception_tenant_idx ON recon_exception (tenant_id);
ALTER TABLE recon_exception ENABLE ROW LEVEL SECURITY;

-- Invariants that cannot be expressed as column constraints are listed here
-- and are enforced by the owning service plus property tests.

--   [tenant] code 创建后不可变
--   [tenant] suspended 租户不得创建新的 PaymentIntent
--   [tenant] closed 租户只允许只读查询与对账
--   [project] (tenant_id, code) 唯一
--   [project] callback_domains 非空且必须是已登记域名
--   [project] 项目不得存储商品或库存信息
--   [merchant] settlement_mode 只能是 direct_to_merchant（NN-13）
--   [merchant] terminated 商户不得发起新支付
--   [provider_account] credential_ref 必须以 kms:// 或 vault:// 开头（NN-07）
--   [provider_account] (tenant_id, merchant_id, provider, environment) 唯一
--   [provider_account] sandbox 与 production 凭证不得共用记录
--   [payment_intent] (project_id, external_reference) 唯一（NN-01）
--   [payment_intent] amount_minor > 0
--   [payment_intent] captured_amount_minor <= amount_minor
--   [payment_intent] refunded_amount_minor <= captured_amount_minor
--   [payment_intent] 状态只允许声明的单向或补偿式转换
--   [payment_intent] 不得包含商品、库存或履约字段（NN-01）
--   [payment_intent] 成功状态只能由验签渠道事件或服务端查询写入（NN-03）
--   [payment_attempt] unknown 状态必须触发主动查询直到收敛（NN-03）
--   [payment_attempt] (provider, provider_transaction_id) 在非空时唯一
--   [payment_attempt] request_digest 不得包含凭证或卡数据（NN-14）
--   [refund] sum(refund.amount_minor) <= payment_intent.captured_amount_minor
--   [refund] amount_minor > 0
--   [refund] approved_by 必须不同于发起人（NN-11）
--   [refund] idempotency_key 唯一
--   [dispute] provider_dispute_id 唯一
--   [dispute] 状态变化必须产生账本分录
--   [subscription] interval_count > 0
--   [subscription] mandate_ref 不得是明文支付令牌（NN-02）
--   [subscription] canceled/ended 订阅不得再产生扣款
--   [ledger_account] (tenant_id, code, currency) 唯一
--   [ledger_account] 平台不得存在自有资金池类型科目（NN-13）
--   [ledger_transaction] (tenant_id, source_kind, source_id) 唯一，防止重复过账（NN-04）
--   [ledger_transaction] 分录一经写入禁止 UPDATE/DELETE（NN-06）
--   [ledger_transaction] adjustment 必须同时具备 reason 与 approved_by
--   [ledger_entry] amount_minor > 0
--   [ledger_entry] 同一 transaction 内 sum(debit) == sum(credit)（按币种）
--   [ledger_entry] 分录不可变（NN-06）
--   [ledger_entry] currency 必须等于 account.currency
--   [recon_run] (tenant_id, provider, business_date, source_file_digest) 唯一
--   [recon_run] 同一文件重复摄取不得产生重复记录
--   [recon_exception] 每条差异必须有分类，不允许 unknown
--   [recon_exception] written_off 必须具备 resolution_reason 与 approved_by（NN-11）
