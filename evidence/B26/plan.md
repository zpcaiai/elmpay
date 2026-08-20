# B26 plan — 商户渠道账户与凭证绑定

Batch: 商户渠道账户与凭证绑定 · Wave W03 · Skill `pay-provider-account-capabilities` · depends_on: [B24]

## 1. 范围

批次目标是「按租户、项目、环境和渠道隔离商户账户，禁止共享密钥与跨租户回调」。
隔离的难点不在写入侧——写入时四个维度都在手上；难点在**回调进来的那一刻**：
回调带的是**渠道自己的标识**，不是我们的。于是归属是一次查找，
而查找可能返回 0 条、1 条或多条。**返回多条时唯一正确的答案是「我不知道」**。
任何「取最像的一个」都能通过所有测试，直到两个租户在同一秒收到同一金额——
然后一个商户的钱被记到另一个商户名下，记录里没有任何痕迹说明记反了。

1. `governance/provider-accounts.json`：绑定四维、5 个渠道、凭证规则、回调规则、
   隔离区、激活条件、4 状态生命周期、能力矩阵、禁止项。
2. `tools/paygov/accounts.py`：绑定门禁（71 条规则码），含五条跨批次校验——
   渠道密钥必须在 B20 的 `keys` 与 `provider_keys` 中、环境必须来自 B24、
   结算币种必须在 B09 货币元数据中、凭证轮换不得慢于 B20 包裹它的 KEK、
   轮换权限必须在 B19 是双人控制、审计类别必须在 B23 存在。
3. `libs/provider/reference/binding.py`：**可执行的归属模型**——三个答案，没有第四个。
4. `tools/paygov/accountsgen.py` + `scripts/render-accounts.py`。
5. `scripts/accounts-smoke.py`：38 项运行期断言。
6. `tools/tests/test_b26_accounts.py`：145 个用例。
7. `tools/negative/b26.py`：27 个负向控制场景。

## 2. 受影响组件

`governance/{provider-accounts,ssot-registry}.json`、`tools/paygov/{accounts,accountsgen}.py`、
`libs/provider/`、`scripts/{render-accounts,accounts-smoke}.py`、
`contracts/provider/account-binding.json`、`docs/provider/PROVIDER_ACCOUNTS.md`、
`tools/tests/test_b26_accounts.py`、`tools/negative/b26.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **归属只有三个答案**：唯一命中 → 投递；零命中 → 隔离；多命中 → 隔离。
  `attribute()` 没有参数能让它猜，`ACCOUNT_CALLBACK_GUESSED` 与
  `ACCOUNT_ATTRIBUTION_HEURISTIC` 从治理侧堵住同一条路。
- **验签只对这一个绑定自己的凭证做**，不是对全库凭证轮一遍——
  否则 A 租户泄露的密钥就能给 B 租户注入一笔支付。顺序也是契约的一部分：
  **先归属、再验签、再幂等、最后交付**。
- **轮换必须有重叠期**。切换瞬间在途的回调是用旧密钥签的，
  而那些回调正是平台证明自己收过钱的唯一凭据；没有重叠期的轮换等于自己删证据。
- **激活是一次真实往返**：测试交易结算 + 回调回来 + 验签通过。
  三者缺一，第一笔真实支付就成了联调。
- **停用不断开回调**（与 B24「停用不等于断电」同源）；**吊销先结清在途再销毁凭证**。

## 4. 错误语义

`ACCOUNT_UNREADABLE`、`ACCOUNT_SHAPE`、`ACCOUNT_VERSION_FIELD`、`ACCOUNT_PRINCIPLE`、
`ACCOUNT_BINDING_DIMENSIONS`、`ACCOUNT_BINDING_NOT_UNIQUE`、`ACCOUNT_BINDING_MUTABLE`、
`ACCOUNT_MULTI_CREDENTIAL`、`ACCOUNT_BINDING_NOTES`、`ACCOUNT_PROVIDER_ID`、
`ACCOUNT_PROVIDER_DUPLICATE`、`ACCOUNT_PROVIDER_KEY_UNKNOWN`、`ACCOUNT_PROVIDER_KEY_UNBOUND`、
`ACCOUNT_CREDENTIAL_KIND`、`ACCOUNT_PROVIDER_NO_ENV`、`ACCOUNT_ENV_UNKNOWN`、
`ACCOUNT_PROVIDER_NO_CURRENCY`、`ACCOUNT_CURRENCY_UNKNOWN`、`ACCOUNT_NO_ATTRIBUTION_FIELD`、
`ACCOUNT_CALLBACK_UNSIGNED`、`ACCOUNT_PROVIDER_ROTATION`、`ACCOUNT_PROVIDER_NOTES`、
`ACCOUNT_PLAINTEXT_CREDENTIAL`、`ACCOUNT_CREDENTIAL_STORAGE`、`ACCOUNT_SHARED_CREDENTIAL`、
`ACCOUNT_LEASE_UNBOUNDED`、`ACCOUNT_ROTATION_UNBOUNDED`、`ACCOUNT_ROTATION_NO_OVERLAP`、
`ACCOUNT_ROTATION_SLOWER_THAN_KEY`、`ACCOUNT_CREDENTIAL_NOTES`、`ACCOUNT_CALLBACK_GUESSED`、
`ACCOUNT_NO_QUARANTINE`、`ACCOUNT_CROSS_TENANT_CALLBACK`、`ACCOUNT_RETURN_PAGE_EVIDENCE`、
`ACCOUNT_REPLAY_WINDOW`、`ACCOUNT_NO_IDEMPOTENCY_KEY`、`ACCOUNT_CALLBACK_NOTES`、
`ACCOUNT_QUARANTINE_UNRETAINED`、`ACCOUNT_QUARANTINE_SILENT`、`ACCOUNT_QUARANTINE_AUTO_REPLAY`、
`ACCOUNT_QUARANTINE_BLIND_REPLAY`、`ACCOUNT_ACTIVATION_UNPROVEN`、`ACCOUNT_ACTIVATION_NOTES`、
`ACCOUNT_STATES`、`ACCOUNT_INITIAL_STATE`、`ACCOUNT_TERMINAL_STATE`、
`ACCOUNT_TRANSITION_UNKNOWN`、`ACCOUNT_TRANSITION_DUPLICATE`、`ACCOUNT_TRANSITION_UNGUARDED`、
`ACCOUNT_TRANSITION_NOTES`、`ACCOUNT_REINSTATE_SINGLE_PERSON`、
`ACCOUNT_REVOKE_BEFORE_SETTLEMENT`、`ACCOUNT_REVOKE_KEEPS_CREDENTIAL`、
`ACCOUNT_STATE_UNREACHABLE`、`ACCOUNT_NO_CAPABILITY_MATRIX`、`ACCOUNT_CAPABILITY_MISSING`、
`ACCOUNT_CAPABILITY_NOTES`、`ACCOUNT_PENDING_TAKES_MONEY`、`ACCOUNT_SUSPENDED_TAKES_MONEY`、
`ACCOUNT_SUSPENDED_BLOCKS_CALLBACKS`、`ACCOUNT_SUSPENDED_STRANDS_MONEY`、
`ACCOUNT_REVOKED_ACTIVE`、`ACCOUNT_FORBIDDEN_RELAXED`、`ACCOUNT_ATTRIBUTION_HEURISTIC`、
`ACCOUNT_FORBIDDEN_NOTES`、`ACCOUNT_PERMISSION_UNKNOWN`、`ACCOUNT_ROTATION_SINGLE_PERSON`、
`ACCOUNT_AUDIT_CLASS_UNKNOWN`、`ACCOUNT_GENERATED_MISSING`、`ACCOUNT_GENERATED_DRIFT`、
`ACCOUNT_GENERATED`。

运行期拒绝码：`DENY_UNKNOWN`、`DENY_DUPLICATE_BINDING`、`DENY_IMMUTABLE`、
`DENY_SHARED_CREDENTIAL`、`DENY_NOT_ALLOWED`、`DENY_TRANSITION`、`DENY_REQUIREMENT`、
`DENY_SELF_APPROVAL`、`DENY_LEASE_EXPIRED`、`DENY_CREDENTIAL_DESTROYED`、
`SIGNATURE_INVALID`、`CALLBACK_STALE`、`ATTRIBUTION_NONE`、`ATTRIBUTION_AMBIGUOUS`、
`DENY_CROSS_TENANT`、`DENY_RETURN_PAGE`、`DENY_BLIND_REPLAY`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify provider-accounts --repo .
python3 scripts/render-accounts.py --check
python3 scripts/accounts-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 绑定 → 装凭证 → 往返验证 → 激活 → 收到回调 → 唯一归属 → 投递 |
| **归属** | 唯一命中投递；零命中隔离；**多命中隔离且双方都没被记账**；缺归属字段、未知渠道、另一环境的同名商户号——都不匹配 |
| 幂等 | 渠道重发返回 `DUPLICATE`；隔离后人工重放同一事件号仍是 `DUPLICATE` |
| **隔离区** | 无归属的人工重放被拒（`DENY_BLIND_REPLAY`）；指名绑定后可重放并出队 |
| 验签 | 错密钥被拒；**另一租户的密钥也被拒**；超时窗被拒；回跳页被拒；跨租户投递被拒 |
| 绑定 | 五个身份字段逐个改都被拒；可变字段可改；同租户同渠道不能有两条；未知渠道/环境不能绑 |
| 凭证 | 同一份凭证不能装两处；轮换需双人；重叠期内新旧密钥都收；重叠期结束旧密钥失效；租约到期不可用；吊销后无凭证可租 |
| 生命周期 | 待验证不能收款；缺往返验证不能激活；未声明的跃迁被拒；单人不能恢复；在途未结清不能吊销；吊销后销毁凭证 |
| 拒绝 | 71 条规则各有用例：绑定丢掉环境维度、唯一键更粗、绑定可变、渠道密钥不存在、渠道不在 B20 表中、币种不在 B09、凭证跨租户共享、明文落盘、租约无限、轮换无重叠、轮换慢于 KEK、歧义时猜测、回跳页当证据、隔离区自动重放、停用断回调、吊销仍可用…… |
| 跨批次 | B20 把 KEK 轮换改成 30 天 → `ACCOUNT_ROTATION_SLOWER_THAN_KEY`；B20 删掉 `wechat` 的 provider_keys → `ACCOUNT_PROVIDER_KEY_UNBOUND`；B19 撤掉 `config.write` 双人 → `ACCOUNT_ROTATION_SINGLE_PERSON`；审计类别不在 B23 → `ACCOUNT_AUDIT_CLASS_UNKNOWN` |
| 失败关闭 | 模型坏到无法生成契约时 `ACCOUNT_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `accounts-smoke.py` 38 项断言；负向控制新增 27 个 B26 场景，共 289 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-accounts.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **验签是占位实现**。参考实现用共享密钥 HMAC，而真实渠道用 RSA-PSS / ECDSA
  （见 B20 `provider_keys`）。本批次证明的是**验签发生在什么位置**（归属之后、状态变更之前），
  不是算法本身；换成真实算法不改变任何一条断言的结构。
- **没有网络、没有存储、没有真实渠道**。`Bindings` 是进程内对象，
  `deliver()` 不写任何库；真正的唯一约束、并发投递、乱序回调、超长重试都属于实现批次。
- **`delivered` 是一个内存字典**。真实幂等需要持久化的唯一约束 + 事务边界，
  否则两个进程同时收到同一次重发仍会双写——**这是本批次没有解决的问题**。
- **隔离区没有容量与背压模型**。如果渠道配置错误导致每笔回调都无法归属，
  隔离区会无限增长；真实系统需要速率告警与熔断，本批次只要求「必须告警」。
- **归属字段是每渠道一个字符串**。真实渠道可能需要**复合键**
  （例如 Stripe 的 `account + endpoint`），模型目前只支持单字段；
  一旦需要复合键，`candidates()` 与治理结构都要改。
- **能力矩阵只有 5 个能力**，且**矩阵自身的完整性无人守护**——
  与 B22 §8、B24 §8、B25 §8 同源的缺口：清单能被检查，清单有没有漏项不能。
- **轮换重叠期没有上限规则**。规则只要求 `0 < overlap < rotation`，
  一个 89 天的重叠期能通过门禁，但它实际上等于「两把密钥永远同时有效」。

## 9. 数据迁移

无。真实落地时需要为现有渠道账户回填四维绑定与凭证引用，属于实现批次。

## 10. 证据与审查

`evidence/B26/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B25 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **回调进来** | 归属靠猜 → 两个租户同金额同秒时把钱记反，且记录里看不出来 | 三个答案没有第四个；`ACCOUNT_CALLBACK_GUESSED` + `ACCOUNT_ATTRIBUTION_HEURISTIC` 双向堵死；歧义进隔离区并告警 |
| 一把密钥服务所有商户 | 一次泄露波及全部租户 | 凭证不跨租户/环境/项目；同一份密钥不能装在两个绑定上 |
| 用回跳页确认支付 | 付款人自己的浏览器就能伪造「已支付」 | `client_return_page_is_evidence=false`；参考实现直接拒绝非渠道来源 |
| 轮换渠道密钥 | 单人轮换可静默改变资金去向；无重叠期会丢掉在途回调 | 轮换需 B19 双人控制；重叠期内旧密钥仍可验签 |
| 停用一个渠道账户 | 顺手关掉回调 → 平台丢掉自己已收款的证据 | 能力矩阵强制停用状态下回调/退款/结算为真 |
| 吊销一个渠道账户 | 先销毁凭证 → 在途交易再也收不到终态 | 吊销必须先 `in_flight_settled`，再 `credential_destroyed` |
