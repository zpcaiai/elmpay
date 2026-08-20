<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/tenant-registry.json
     Regenerate with: python3 scripts/render-tenants.py -->

# 租户与项目注册中心（B24）

多租户平台出事的地方从来不是「租户 A 读到了租户 B」这种正面攻击，而是三个边角：**停用**（停掉一个租户时，它已经收的钱、待退的款、渠道还会回调的通知怎么办）、**注销**（删掉一个租户，但删不掉它做过什么的记录）、以及**测试与生产**（一把测试密钥打到了真实资金上）。因此这里定义的不是「租户有哪些字段」，而是**层级、生命周期与不可跨越的边界**：公司 → 租户 → 项目 → 环境，环境之间不共享任何密钥，租户注销靠销毁它自己的 KEK，而账本与审计按各自的保留期独立存活。

## 层级

| 层 | 前缀 | 父级 | 说明 |
| --- | --- | --- | --- |
| organisation | `org_` | — | 法人主体。KYB 与合同在这一层，因此它是计费与合规的边界。 |
| tenant | `ten_` | organisation | 隔离边界。每个租户有自己的 KEK、自己的行级安全谓词、自己的审计链——**跨租户引用在任何一层都不允许**。 |
| project | `prj_` | tenant | 一个租户下的独立业务线，共享租户的隔离边界但有各自的配置与配额。 |
| environment | `env_` | project | live 或 test。**环境之间不共享密钥、不共享数据、不共享凭据**；这一条是本批次唯一一条「没有例外」的规则。 |

## 标识符

- 模式：`^(org|ten|prj|env)_[0-9a-hjkmnp-tv-z]{16}$`
- 不透明：是；不可变：是

标识符不透明且不可变：把租户名、国家或序号编进 ID，等于把商业信息发给每一个能看到 URL 的人，也让「改名」变成「改主键」。字母表去掉 i/l/o/u，避免人工转录出错与生成脏话。

## 环境

| 环境 | 真实资金 | 共享密钥 | 共享数据 |
| --- | --- | --- | --- |
| `live` | 是 | 无 | 无 |
| `test` | 否 | 无 | 无 |

- **`live`**：真实资金。
- **`test`**：沙箱。**测试凭据在 live 上必须无效**，反之亦然——这类事故的典型形态是「同一把密钥两个环境都认」。

## 生命周期

`draft` → `active` → `suspended` → `offboarding` → `closed`

| 从 | 到 | 前置条件 | 说明 |
| --- | --- | --- | --- |
| `draft` | `active` | `kyb_verified`、`contract_signed` | 未完成 KYB 的租户不得进入 active（KYB 数据模型在 B25）。 |
| `active` | `suspended` | `reason`、`actor` | 停用是可逆的，且必须有理由与操作人。 |
| `suspended` | `active` | `reason`、`actor`、`second_approver` | 恢复需要第二个人：停用往往因风控或合规，单人恢复等于单人推翻风控。 |
| `suspended` | `offboarding` | `reason`、`actor`、`second_approver` | 从停用直接进入注销流程；与恢复走同一道四眼复核，因为这两条路的分叉点是同一个决定。 |
| `active` | `offboarding` | `reason`、`actor`、`second_approver` | 商户主动离开。仍然要第二个人：注销会触发密钥销毁，是不可逆的。 |
| `offboarding` | `closed` | `settlement_complete`、`retention_period_started`、`kek_destroyed` | **只有在结算完成之后**才能关闭：先销毁密钥再结算，等于把钱锁死在自己账上。 |

## 各状态下还能做什么

| 状态 | 收款 | 退款 | 接收回调 | 结算 | 读数据 |
| --- | --- | --- | --- | --- | --- |
| `draft` | — | — | — | — | ✅ |
| `active` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `suspended` | — | ✅ | ✅ | ✅ | ✅ |
| `offboarding` | — | ✅ | ✅ | ✅ | ✅ |
| `closed` | — | — | — | — | — |

- **`draft`**：只能配置，不能收钱。
- **`active`**：正常经营：收款、退款、回调、结算全开。这一行是基准，其它每一行都要能解释自己相对它少了什么、为什么。
- **`suspended`**：**停用不等于断电**：新支付停止，但退款、渠道回调与结算必须继续——否则被停用的租户的付款人拿不回钱，而钱已经在路上。这是本批次最容易被写错的一格。
- **`offboarding`**：同上，且不再接受新配置。
- **`closed`**：数据已密码学销毁；账本与审计记录按各自保留期独立留存，读取需要平台侧的紧急通道。

## 配额

| 配额 | 作用域 | 默认 | 硬上限 |
| --- | --- | --- | --- |
| `api_keys_per_environment` | environment | 10 | 50 |
| `payments_per_minute` | project | 600 | 60000 |
| `projects_per_tenant` | tenant | 20 | 200 |
| `webhook_endpoints_per_project` | project | 5 | 20 |

- **`payments_per_minute`**：限流按项目而不是租户：一个项目被刷不应该让同租户的另一条业务线一起挂。
- **`api_keys_per_environment`**：密钥数量本身就是攻击面。
- **`webhook_endpoints_per_project`**：回调端点越多，未验签端点被遗忘的概率越大。
- **`projects_per_tenant`**：上限存在的意义是让「批量建项目」这种异常行为可被发现。

## 隔离

隔离由三样东西共同保证：B13 的强制行级安全、B20 的每租户 KEK、以及这里禁止的跨租户外键。任何一样缺失，另外两样都会被绕过。

## 注销

注销顺序是不可交换的：结算完成 → 冷静期 → 销毁 KEK → 关闭。账本与审计记录不随租户消失，因为它们记录的是**平台做过什么**，不只是租户的数据。

## 命名

展示名可改、可重名（跨组织），标识符不可改、全局唯一。把两者混为一谈是「改个名字导致对账断裂」的根源。
