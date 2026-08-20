<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/authorization.json
     Regenerate with: python3 scripts/render-authz.py -->

# 授权、职责分离与限时提权（B19）

授权的默认答案是「拒绝」。一个主体能做什么，必须由**明确授予**的权限、**它自己的租户**、**这一个对象**和**这一个字段**四层共同决定；而资金类动作还要再加一层：**提出的人不能是批准的人**。角色清单在这里是唯一事实源——一个角色被标记为特权，它的 MFA 要求、恢复路径和零信任主体就必须真实存在，否则门禁不放行。

## 角色

| 角色 | 类型 | 范围 | 特权 | 零信任主体 | 常驻权限 |
| --- | --- | --- | --- | --- | --- |
| `platform-operator` | human | platform | ✅ | `platform-operator` | `audit_log.read`、`payment.read`、`risk_decision.override` |
| `break-glass` | human | platform | ✅ | `break-glass` | `audit_log.read` |
| `merchant-admin` | human | tenant | ✅ | `merchant-api-client` | `customer_pii.read`、`payment.create`、`payment.read`、`payout_account.write`、`refund.request` |
| `merchant-finance` | human | tenant | ✅ | `merchant-api-client` | `bank_account.read`、`payment.read`、`payout.approve`、`reconciliation.approve`、`refund.approve` |
| `risk-analyst` | human | platform | ✅ | `platform-operator` | `payment.read`、`risk_rule.write` |
| `support-agent` | human | tenant | — | `merchant-api-client` | `customer_pii.read`、`payment.read`、`refund.request` |
| `auditor` | human | platform | — | `platform-operator` | `audit_log.read`、`payment.read` |
| `payer` | human | self | — | `payer` | `payment.create` |
| `payment-core-service` | service | platform | — | `service-workload` | `payment.create`、`payment.read` |

- **`platform-operator`**：平台运营。可以跨租户读支付事实，但**读不到卡号，也读不到未脱敏的个人信息**；改平台配置**不是常驻权限**，必须走限时提权。
- **`break-glass`**：紧急通道账号。**平时几乎没有权限**——它的价值来自提权流程本身：每一次使用都有票据、有审批、有时限、有事后复核。常驻权限会让紧急通道变成一条日常后门。
- **`merchant-admin`**：商户管理员。可以改收款账户（资金去向），因此该权限必须双人复核；可以发起退款但**不能自己批准**。
- **`merchant-finance`**：商户财务。批准退款与出款，是职责分离里的「复核方」；因此**不得**同时持有 refund.request 与 payout_account.write。
- **`risk-analyst`**：风控分析师。写规则的人不能同时是能推翻规则判定的人，否则「规则」只是他自己的一句话。
- **`support-agent`**：客服。可以发起退款、看脱敏后的联系方式；**看不到卡号、看不到银行账号全文**。客服席位是社会工程学最常见的入口，权限必须最小。
- **`auditor`**：审计员。只读，且不可提权——审计的价值来自它**不能**改变被审计的东西。
- **`payer`**：付款人。只能创建属于自己的支付，看不到任何他人的数据。
- **`payment-core-service`**：服务身份。凭据由工作负载身份签发（B17），不持有任何资金审批权限——服务账号被攻陷时不应该能批钱。

## 权限

| 权限 | 层级 | 敏感度 | 双人复核 | 需提权 |
| --- | --- | --- | --- | --- |
| `payment.read` | tenant | normal | — | — |
| `payment.create` | tenant | normal | — | — |
| `refund.request` | object | money | — | — |
| `refund.approve` | object | money | ✅ | — |
| `payout_account.write` | object | money | ✅ | — |
| `payout.approve` | object | money | ✅ | — |
| `ledger.adjust` | object | money | ✅ | ✅ |
| `reconciliation.approve` | object | money | ✅ | — |
| `risk_rule.write` | platform | high | ✅ | — |
| `risk_decision.override` | object | high | ✅ | — |
| `cross_tenant_data.read` | platform | high | ✅ | ✅ |
| `customer_pii.read` | field | high | — | — |
| `bank_account.read` | field | high | — | — |
| `audit_log.read` | platform | normal | — | — |
| `config.write` | platform | high | ✅ | ✅ |

## 字段级规则

| 字段 | 分类 | 永不可读 | 默认脱敏 | 可读全文的角色 |
| --- | --- | --- | --- | --- |
| `card_pan` | pan | ✅ | ✅ | （无） |
| `card_cvv` | cvv | ✅ | ✅ | （无） |
| `bank_account_number` | financial | — | ✅ | `merchant-finance` |
| `customer_email` | pii | — | ✅ | `merchant-admin`、`support-agent` |
| `customer_phone` | pii | — | ✅ | `merchant-admin`、`support-agent` |

- **`card_pan`**：卡号在本平台**任何角色都读不到**（NN-04）。它不是权限问题，是它根本不该以明文存在于可读路径上。
- **`card_cvv`**：CVV 不存储、不可读、不入日志。
- **`bank_account_number`**：默认只给后四位；只有财务角色能看全文，且每次读取都留审计。
- **`customer_email`**：默认脱敏。客服能看是为了办事，不是为了浏览。
- **`customer_phone`**：默认只给后四位。手机号是账号接管与社会工程学的入口，客服能看是为了办事，不是为了浏览。

## 职责分离

| 编号 | 不得由同一人同时持有 | 说明 |
| --- | --- | --- |
| SOD-01 | `refund.request` + `refund.approve` | 发起退款的人不能批准自己的退款——这是最基本的一条，也是最常被「临时」破例的一条。 |
| SOD-02 | `payout_account.write` + `payout.approve` | 改钱的去向与放钱出去必须是两个人：一个人同时持有这两项，就等于可以把任意一笔款打到自己的账户。 |
| SOD-03 | `ledger.adjust` + `reconciliation.approve` | 能调账的人不能批准对账，否则差异可以被自己抹平，账实不符永远不会被发现。 |
| SOD-04 | `risk_rule.write` + `risk_decision.override` | 写规则与推翻规则判定必须分开。 |
| SOD-05 | `risk_rule.write` + `refund.approve` | 能写风控规则的人如果还能批退款，他可以先写一条让自己的退款自动通过的规则。 |

## 双人复核

- 最少审批数：1；审批人必须不同于申请人：是
- 审批有效期：900 秒；绑定请求摘要：是

审批必须绑定**这一次请求的摘要**：不绑定的审批只能证明「有人批过某件事」，会被复用到另一笔上。这与 B18 的 step-up 交易绑定是同一个道理。

## 限时提权（JIT）

- 常驻特权：**不允许**
- 最长时限：60 分钟；到点自动收回：是
- 需审批：是；需票据：是
- 可提权的权限：`config.write`、`cross_tenant_data.read`、`ledger.adjust`
- 不可提权的角色：`auditor`、`payer`、`payment-core-service`

不存在常驻特权。提权必须有审批人（且不是申请人自己）、有票据、有时限、到点自动收回。

### 紧急通道（`break-glass`）

- 最长 30 分钟，事后 24 小时内必须复核
- 通知渠道：`security_team`、`on_call`、`audit_log`

紧急通道的时限比常规提权更短，且**每一次使用都必须在 24 小时内被人复核**。不复核的紧急通道等于常驻管理员。

## 审计

允许与拒绝都要记录，并带上规则版本——事后要能回答「当时为什么放行」，而不是「现在的规则会不会放行」。

## 资金类权限清单（供审查者速查）

`ledger.adjust`、`payout.approve`、`payout_account.write`、`reconciliation.approve`、`refund.approve`、`refund.request`
