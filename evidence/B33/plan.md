# B33 plan — 支付尝试与渠道交易

Batch: 支付尝试与渠道交易 · Wave W04 · Skill `pay-payment-intents-attempts` · depends_on: [B32]

## 1. 范围

本批次把一次渠道调用建模为一条可解释、租户隔离的 attempt。核心不是“失败后再试”，
而是先区分**明确失败**与**结果未知**：超时或断连可能发生在渠道已经扣款之后，
因此未知结果必须先经主动查询或对账落定，不能直接再发一次扣款调用。

交付包括机器可读治理模型、生成的语言中立契约与审查文档、零依赖 Python 参考语义、
治理门禁、负向控制、运行期场景以及全量回归证据。这里只实现可执行参考语义，
不把它描述成已部署的支付服务。

## 2. 受影响组件

- `governance/payment-attempt.json`：attempt、租户边界、并发策略、请求/响应留存、
  结果分类、超时落定、重试、最终性、生命周期和参考运行时边界。
- `tools/paygov/{attempt,attemptgen}.py`：fail-closed 校验器和生成器。
- `contracts/payment/attempt.json`、`docs/payment/PAYMENT_ATTEMPT.md`：生成产物。
- `libs/attempt/reference/attempt.py`：可执行的内存参考实现。
- `scripts/{render-attempt,attempt-smoke}.py`：漂移与运行期证明。
- `tools/tests/test_b33_attempt.py`、`tools/negative/b33.py`：正常、拒绝、并发与安全测试。

## 3. 领域接口与数据契约

- 每次渠道调用创建新的内部 `attempt_id`，内部 ID 独立生成，不复用 tenant、intent 或渠道 ID。
- 所有读取与状态变化显式带 `tenant_id`；查找与冲突键均为
  `(tenant_id, intent_id)`，相同 `intent_id` 在不同租户下互不可见。
- attempt 在每笔 intent 内持有单调 `sequence`。同一请求的传输重试新建记录但复用渠道幂等键；
  客户更换资金源/重新授权是 replacement request，只能在明确拒绝后发生，并必须使用新幂等键。
- 请求只保留去除敏感字段后的 SHA-256 摘要，不保留或重放原始请求。
- 响应只保留渠道请求号、交易号、**码命名空间**、渠道码、规范化结果分类及其摘要；
  原始响应体、响应头、凭证、令牌、PAN 与 CVV 均禁止进入记录。
- 分类为 `succeeded`、`failed_final`、`failed_retryable`、`unknown`。
  未登记的 `(provider, namespace, code)` 一律为 `unknown`。
- `final` 描述 attempt 是否终结，不等于把 PaymentIntent 落为终态；只有
  `settles_intent=true` 的分类能决定 intent。成功会落定 intent，普通渠道拒绝只结束本次请求。
- 超时为 `unknown`，会阻止后续 attempt，直到 `provider_query` 或
  `reconciliation_file` 落定；矛盾的后到事件开对账项，不覆盖历史。
- 同一租户/意图的并发 `start` 原子化；参考实现用进程内锁保证只有一个创建成功，
  生产实现必须换成数据库唯一约束或等价的分布式原子机制。

## 4. 错误语义

治理规则以 `ATTEMPT_*` 码 fail closed，重点包括：
`ATTEMPT_TENANT_LOOKUP_UNSCOPED`、`ATTEMPT_START_NOT_ATOMIC`、
`ATTEMPT_CONCURRENT_DUPLICATE_CALL`、`ATTEMPT_FIELD_MISSING`、
`ATTEMPT_RESPONSE_EVIDENCE_MISSING`、`ATTEMPT_RESPONSE_PAYLOAD_STORED`、
`ATTEMPT_TIMEOUT_IS_FAILURE`、`ATTEMPT_UNKNOWN_RETRYABLE`、`ATTEMPT_REUSED`、
`ATTEMPT_NEW_KEY_ON_RETRY`、`ATTEMPT_FAILURE_SETTLES_INTENT`、
`ATTEMPT_REPLACEMENT_SCOPE`、`ATTEMPT_REPLACEMENT_REUSES_KEY`、
`ATTEMPT_REPLACEMENT_NO_CUSTOMER_ACTION`、`ATTEMPT_CODE_NAMESPACE`、
`ATTEMPT_UNMAPPED_IS_SUCCESS`、
`ATTEMPT_FINAL_MUTABLE`、`ATTEMPT_CONTRADICTION_IGNORED`、
`ATTEMPT_STATES_DIVERGE`、`ATTEMPT_RETURN_PAGE_EVIDENCE` 和
`ATTEMPT_REFERENCE_OVERCLAIM`。

参考运行时拒绝使用稳定的领域码，例如租户缺失/不匹配、未知未落定、attempt 已终态、
不可重试、重试耗尽、幂等键改变、请求号/交易号重复、响应未记录和非法跃迁。

## 5. 命令

```bash
python3 .payment-platform/skill-package/scripts/verify_package.py
python3 -m tools.paygov.cli verify payment-attempt --repo .
python3 scripts/render-attempt.py --check
python3 scripts/attempt-smoke.py
python3 scripts/test-summary.py --shard 1/4 --out evidence/B33/test-results/summary-1of4.json
python3 scripts/negative-controls.py --shard 1/4
python3 scripts/rule-knockout.py --codes ATTEMPT_TIMEOUT_IS_FAILURE,ATTEMPT_START_NOT_ATOMIC
python3 scripts/batch.py crosscheck
```

完整、可执行的命令与预期退出码在 `evidence/B33/commands.spec.json`；长测试与负向控制
按 4 个互斥且穷尽的 shard 记录，测试摘要只有在四片精确覆盖全部发现单元时才合并成功。

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 新 attempt、单调序号、请求摘要、规范化响应证据、成功/拒绝/可重试分类、查询落定 |
| 超时 | 超时成为 unknown；落定前拒绝下一次渠道调用；未知码默认 unknown |
| 幂等与重试 | 同一请求重试复用幂等键；更换资金源必须是明确客户动作并使用新键；两者都新建 attempt 且受总上限约束 |
| 租户 | 同名 intent 在两个租户下隔离；跨租户读取、落定、后到事件与对账读取均拒绝 |
| 并发 | 多个线程竞争同一 tenant/intent，精确一条 attempt 成功，其余在渠道调用前拒绝 |
| 最终性 | 终态所有字段不可直接改写；矛盾后到事件开对账项且不覆盖原判断 |
| 敏感数据 | 原始请求/响应均不可读取；摘要和规范化证据不包含受禁字段 |
| 负向控制 | 逐项破坏租户键、原子策略、摘要、响应留存、超时、重试、分类、最终性与 B10/B32 绑定 |
| 删除击杀 | 关键 `ATTEMPT_*` 规则逐个移除后，对应测试必须失败 |
| 失败关闭 | 生成物漂移与预算耗尽分别退出非零；全量治理输出重复执行字节一致 |

## 7. 回滚

本批次只新增治理模型、生成文件、参考实现与测试，无数据库写入。回滚使用提交级 revert，
随后运行 `scripts/render-attempt.py` 和全量治理门禁确认 B32 仍保持原状态。
不要只删除生成文件而保留 SSOT，也不要保留一半的错误分类表。

## 8. 已知限制（诚实声明）

- 参考实现使用内存列表与进程内锁；没有持久存储、数据库唯一约束、跨进程锁或崩溃恢复，
  `production_ready=false`。它证明领域语义，不证明生产并发安全。
- `audit_event_class=money.movement` 只证明与 B23 审计分类绑定；没有运行中的审计 sink、
  outbox/inbox 或不可篡改存储。
- 响应摘要覆盖**规范化响应证据**，不是渠道原始字节；本批次有意不保存原始响应，
  因而不能用该摘要证明原始 HTTP body 的逐字节内容。
- 没有真实渠道 SDK、HTTP 超时、熔断器、服务端主动查询任务或对账文件摄取。
  错误分类表只是受版本控制的最小起点，渠道升级时必须经契约测试更新。
- 24 小时落定上限只有策略和参考方法，没有调度器、告警和升级处置实现。
- `replacement_request=True` 只是参考接口上的显式信号，没有客户会话签名、支付方式指纹或
  服务端授权证据；生产实现必须验证真实客户动作，不能信任调用方布尔值。
- B32 的独立 `Intents.confirm()` 参考实现仍会在已有确认键后拒绝任何新键；它没有接入 B33 的
  replacement 结果，因此“拒绝后换资金源”只在 attempt 模型内成立，尚未形成端到端 intent 流程。
- Apple Pay 的 `DECRYPT_FAILED` 明确是 elmpay/PSP 适配器归一化码，不声称为 Apple 官方错误码。
- 本地自动化审查不能替代项目指定的独立人类复核；没有与当前 HEAD 绑定的复核结论时，
  不生成或宣称 B33 `passed` completion。

## 9. 数据迁移

本批次没有执行数据库迁移。生产落地至少需要租户分区的 `payment_attempt` 表、
`(tenant_id,intent_id,sequence)` 唯一约束、并发开始的原子冲突约束、渠道请求号/交易号唯一约束、
只追加审计/outbox，以及对既有渠道交易的可验证回填。没有真实 PostgreSQL 与迁移演练前，
这些均保持 `NOT_RUN`。

## 10. 证据与审查

自动化证据写入 `evidence/B33/`，并绑定依赖 B32、当前提交、命令谱和产物摘要。
实现者为 Codex 主执行者与 B33 实现子代理；项目配置指定的独立审查者为 `Ethan`，
但本次没有观察到其对当前提交的签署，因此 `evidence/B33/review.json` 不存在、
人类复核状态为 `NOT_RUN`，不据此声称完成或认证。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 引入渠道调用 attempt | 重试覆盖旧行，事后无法解释第一次调用是否扣款 | 每次调用新记录、单调序号、终态封存 |
| 超时/断连 | 把未知当失败立即重试，造成重复扣款 | `unknown` 阻断后续调用，必须查询或对账落定 |
| 多租户共享运行时 | 同名 intent 或外部 ID 混用导致跨租户读取/冲突 | 显式 tenant_id、租户查找键、独立内部 attempt ID、跨租户拒绝测试 |
| 并发确认 | 两个请求同时看见“尚无 attempt”并双双触达渠道 | 原子 start 策略、进程内锁证明、生产唯一约束作为未完成门 |
| 资金源被拒后客户换卡 | 把换卡误当原请求重试会复用旧幂等键；把拒绝误当 intent 终态会错误阻断付款 | attempt 与 intent 最终性分离；replacement request 要求客户动作与新幂等键 |
| 保留渠道证据 | 原始报文把凭证、令牌或卡数据带入日志/数据库 | 请求摘要 + 规范化响应摘要；原始 payload/header 禁止存储 |
| 渠道码重名或升级 | 不同命名空间的同名码误分类，未知码被当成失败/成功 | `(provider, namespace, code)` 三元映射；未知默认 unknown |
| 终态后收到矛盾事件 | 覆盖历史使资金判断不可解释 | 新建对账项，禁止覆盖终态 attempt |
