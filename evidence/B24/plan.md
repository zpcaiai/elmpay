# B24 plan — 租户与项目注册中心

Batch: 租户与项目注册中心 · Wave W03 · Skill `pay-tenant-merchant-registry` · depends_on: [B23]

## 1. 范围

多租户平台出事的地方不是「A 读到了 B」这种正面攻击，而是三个边角：
**停用**、**注销**、**测试与生产**。本批次定义的正是这三处的边界。

1. `governance/tenant-registry.json`：四级层级、标识符规则、两个环境、5 状态生命周期、
   **能力矩阵**、隔离约束、4 类配额、注销顺序。
2. `tools/paygov/tenants.py`：注册中心门禁（47 条规则码），含四条跨批次校验——
   每租户 KEK 必须在 B20 且确实按租户分片、B13 的租户表必须有行级安全、
   B21 必须同样禁止跨环境共享密钥、生命周期审计类别必须在 B23 中存在。
3. `libs/registry/reference/tenants.py`：**可执行的生命周期与能力模型**。
4. `tools/paygov/tenantsgen.py` + `scripts/render-tenants.py`。
5. `scripts/tenants-smoke.py`：26 项运行期断言。
6. `tools/tests/test_b24_tenants.py`：90 个用例。
7. `tools/negative/b24.py`：15 个负向控制场景。

## 2. 受影响组件

`governance/{tenant-registry,ssot-registry}.json`、`tools/paygov/{tenants,tenantsgen}.py`、
`libs/registry/`、`scripts/{render-tenants,tenants-smoke}.py`、
`contracts/tenancy/registry.json`、`docs/tenancy/TENANT_REGISTRY.md`、
`tools/tests/test_b24_tenants.py`、`tools/negative/b24.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **能力矩阵是本批次的核心**，而不是状态机。状态机只有 5 个状态、6 条转移，一眼就懂；
  真正会写错的是「停用之后还能做什么」。
  本平台的答案：**停用停止新支付，但退款、渠道回调、结算必须继续**。
  把停用实现成「一个布尔全关」会让被停用商户的付款人钱已出去、退款路被自己关掉。
  `TENANT_SUSPENDED_BLOCKS_REFUNDS` 就是为这一格存在的。
- **注销的顺序不可交换**：结算完成 → 冷静期 → 销毁 KEK → 关闭。
  先销毁密钥再结算，等于把商户的钱锁死在我们账上。
- **账本与审计不随租户消失**。它们记录的是**平台做过什么**，不只是租户的数据；
  `TENANT_LEDGER_NOT_RETAINED` / `TENANT_AUDIT_NOT_RETAINED` 挡住「删干净」这种要求。
- **环境是硬分区**：live 与 test 不共享密钥、不共享数据，且**没有例外**。
  参考实现里 `credential_valid()` 不接受任何 override——这类「临时调试用」的例外最终都会遇到真钱。
  门禁还会回头检查 B21 是否**也**禁止跨环境共享密钥：只有一边写着，不算控制。
- **标识符不透明且不可变**。把租户名/国家/序号编进 ID，等于把商业信息发给每个能看 URL 的人；
  可变的 ID 会让「改名」变成「改主键」。字母表去掉 `i/l/o/u`。
- **隔离靠三样东西同时成立**：B13 的强制行级安全、B20 的每租户 KEK、这里禁止的跨租户引用。
  少任何一样，另外两样都会被绕过——所以门禁把三样一起检查。
- **配额按项目而不是租户**：一个项目被刷不应该让同租户的另一条业务线一起挂。

## 4. 错误语义

`TENANT_UNREADABLE`、`TENANT_SHAPE`、`TENANT_VERSION_FIELD`、`TENANT_PRINCIPLE`、
`TENANT_HIERARCHY`、`TENANT_PREFIX`、`TENANT_LEVEL_NOTES`、`TENANT_ID_PATTERN`、
`TENANT_ID_NOT_OPAQUE`、`TENANT_ID_MUTABLE`、`TENANT_ENV_MONEY`、`TENANT_ENV_SHARES_KEYS`、
`TENANT_ENV_SHARES_DATA`、`TENANT_STATES`、`TENANT_INITIAL_STATE`、`TENANT_TERMINAL_STATE`、
`TENANT_TRANSITION_UNKNOWN`、`TENANT_TRANSITION_DUPLICATE`、`TENANT_TRANSITION_UNGUARDED`、
`TENANT_TRANSITION_NOTES`、`TENANT_ACTIVATION_UNVERIFIED`、`TENANT_UNSUSPEND_SINGLE_PERSON`、
`TENANT_CLOSE_BEFORE_SETTLEMENT`、`TENANT_CLOSE_WITHOUT_SHREDDING`、`TENANT_STATE_UNREACHABLE`、
`TENANT_NO_CAPABILITY_MATRIX`、`TENANT_CAPABILITY_MISSING`、`TENANT_CAPABILITY_NOTES`、
`TENANT_DRAFT_TAKES_MONEY`、`TENANT_SUSPENDED_BLOCKS_REFUNDS`、`TENANT_SUSPENDED_TAKES_MONEY`、
`TENANT_CLOSED_ACTIVE`、`TENANT_CROSS_REFERENCE`、`TENANT_NO_RLS`、`TENANT_KEK_UNKNOWN`、
`TENANT_KEK_NOT_SCOPED`、`TENANT_NO_QUOTAS`、`TENANT_QUOTA_DUPLICATE`、`TENANT_QUOTA_SCOPE`、
`TENANT_QUOTA_DEFAULT`、`TENANT_QUOTA_CEILING`、`TENANT_QUOTA_NOTES`、
`TENANT_LEDGER_NOT_RETAINED`、`TENANT_AUDIT_NOT_RETAINED`、`TENANT_NO_GRACE_PERIOD`、
`TENANT_AUDIT_CLASS_UNKNOWN`、`TENANT_GENERATED_MISSING`、`TENANT_GENERATED_DRIFT`、
`TENANT_GENERATED`。

运行期拒绝码：`DENY_UNKNOWN_STATE`、`DENY_NOT_ALLOWED`、`DENY_WRONG_ENVIRONMENT`、
`DENY_CROSS_TENANT`、`DENY_TRANSITION`、`DENY_REQUIREMENT`、`DENY_QUOTA`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify tenant-registry --repo .
python3 scripts/render-tenants.py --check
python3 scripts/tenants-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 草稿 → 完成 KYB → 活跃 → 收款；每一步的能力都按矩阵放行 |
| **停用** | 停用后新支付被拒，**退款/回调/结算三项仍然放行**；被禁止的能力抛异常而不是静默返回 |
| 恢复 | 单人无法恢复；四眼复核后恢复成功 |
| **注销** | 结算未完成时关闭被拒；关闭后一切能力关闭且密钥已销毁；关闭后非法跃迁被拒 |
| 环境 | live 凭据在 test 被拒、另一租户的凭据被拒、未知环境被拒；只有 live 处理真实资金 |
| 配额 | 用尽后被拒；按作用域独立计数；自定义上限不得超过硬上限；未知配额被拒；重置后恢复 |
| 拒绝 | 47 条规则各有用例：层级乱序、前缀重复、标识符可读/可变、环境共享密钥或数据、两个环境都处理真钱、初始状态是 active、转移无前置条件、激活不要 KYB、单人恢复、先销毁后结算、状态不可达、能力矩阵缺行或缺项、草稿可收款、停用仍收款、关闭仍可读、跨租户引用、KEK 不按租户分片、配额上限低于默认值、审计类别不存在…… |
| 跨批次 | KEK 不在 B20 → `TENANT_KEK_UNKNOWN`；B21 允许跨环境共享密钥 → `TENANT_ENV_SHARES_KEYS`；审计类别不在 B23 → `TENANT_AUDIT_CLASS_UNKNOWN`；`key-management.json` 损坏时门禁**给出发现而不是崩溃** |
| 失败关闭 | 模型坏到无法生成契约时 `TENANT_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `tenants-smoke.py` 26 项断言；负向控制新增 15 个 B24 场景，共 240 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-tenants.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **KYB 只是一个前置条件的名字**。`kyb_verified` 在这里是转移要求里的一个字符串，
  它的数据模型、证据留存与复核流程属于 **B25**；本批次不验证任何 KYB 内容。
- **没有存储、没有 API**。`Registry` 是进程内对象，`register()` 不会写任何库；
  真正的唯一性约束、并发创建、幂等注册都属于实现批次。
- **配额是计数器不是限流器**。没有时间窗口、没有分布式一致性、没有突发容量；
  `payments_per_minute` 在参考实现里只是「一个作用域下的累计计数」。
- **能力矩阵只覆盖 5 个能力**。真实平台还有导出、结算账户变更、API 密钥签发等等；
  **矩阵的完整性没有被任何规则强制**——这是与 B22 §8 第 5 条同源的缺口：清单自身的完整性无人守护。
- **关闭状态下的读取需要平台紧急通道**，但本批次没有建模那条通道
  （它属于 B19 的 break-glass + B13 的 escape hatch，两者在这里只是被引用）。
- **注销的冷静期是一个天数**，没有建模「冷静期内商户反悔」的恢复路径——
  状态机里没有 `offboarding → active`，这是**有意的**（不可逆更安全），
  但真实业务大概率需要它，届时必须重新评估。

## 9. 数据迁移

无。真实落地时需要为现有租户回填层级与状态，属于实现批次。

## 10. 证据与审查

`evidence/B24/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B23 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **停用一个商户** | 一个布尔全关 → 已付款的人拿不回钱，渠道回调被丢弃，账对不上 | 能力矩阵强制：停用/注销状态下退款、回调、结算三项必须为真 |
| 风控停用后被单人恢复 | 一个人推翻了风控的决定 | 恢复转移必须包含 `second_approver` |
| **注销一个租户** | 先销毁密钥再结算 → 钱锁死；或「删干净」→ 平台自己的记录也没了 | 关闭必须先 `settlement_complete`；账本与审计强制留存 |
| 测试凭据打到生产 | 一行「方便调试」的例外遇上真实资金 | 环境硬分区，无 override；B21 与 B24 双向要求一致 |
| 租户 ID 里编进了名字 | 商业信息随 URL 泄露；改名变成改主键 | 标识符不透明、不可变，有模式校验 |
| 一个租户被刷 | 同平台其它租户一起挂 | 配额按项目/环境切分，有默认值与硬上限 |
| 跨租户外键悄悄出现 | 隔离的三根支柱塌了一根，另外两根会被绕过 | 禁止跨租户引用 + 行级安全 + 每租户 KEK，三者一起检查 |
