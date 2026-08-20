# B10 plan — 支付状态机与业务不变量

Batch: 支付状态机与业务不变量 · Wave W01 · Skill `pay-state-api-contracts` · depends_on: [B08]

## 1. 范围

B08 声明了**有哪些状态**（36 个），B09 声明了**金额意味着多少钱**。
B10 回答前两者都回答不了的问题：**什么可以变成什么、谁有资格这么说、以及怎么重放**。

1. `governance/state-machines.json`：7 台状态机、48 条转移，每条带
   `from/to/event/actor/kind/guard/idempotency/effects`。
2. `tools/paygov/states.py`：状态机门禁（可达性、死角、终态、确定性、信任边界、幂等、补偿式回边）。
3. `libs/statemachine/reference/machine.py`：**可执行参考解释器**。
   规范如果不能被执行，就只是一张图。
4. `tools/paygov/stategen.py` + `scripts/render-states.py` +
   `docs/domain/STATE_MACHINES.md`：由模型生成的评审文档（含 Mermaid 状态图）。
5. `scripts/state-smoke.py`：8 组真实业务场景的运行期证明（24 项断言）。
6. `tools/tests/test_b10_states.py`：58 个用例。

## 2. 受影响组件

`governance/{state-machines,ssot-registry}.json`、`tools/paygov/{states,stategen,registry}.py`、
`libs/statemachine/`、`scripts/{render-states,state-smoke}.py`、`docs/domain/STATE_MACHINES.md`、
`tools/tests/{test_b10_states.py,support.py}`、`scripts/negative-controls.py`（扩至 65 个场景）。
无数据库变更。

## 3. 领域接口与数据契约

- **转移四元组**：`(from, event) → to`，对同一 `(from, event)` 只允许一个结果（确定性）。
- **参与者与信任边界**：7 个参与者，其中只有 `provider-event`（已验签渠道事件或服务端主动查询）
  与 `reconciliation`（对账定责）被标记 `trusted_for_success`。
  `merchant` / `customer` / `operator` / `scheduler` / `system` **一律不能**把对象推进成功状态。
- **成功状态清单**：`PaymentIntent: authorized, captured`；`PaymentAttempt: succeeded`；
  `Refund: succeeded`。这是 NN-03 在模型层的可执行形式。
- **幂等键**：每条转移必须声明幂等键（如 `provider_event_id`、`idempotency_key`、
  `subscription_id+period`）。解释器按 `(event, token)` 去重，重放返回同一状态而不是报错。
- **转移类型**：`forward` 与 `compensating`。凡是让进度倒退的边（目标状态能沿前向边走回源状态）
  必须声明为 `compensating`，且必须列出 effects。
- **退款不改变支付状态**：已捕获仍是已捕获，退款额记在 `refunded_amount_minor`。
  把「已退款」做成支付状态会让部分退款无法表达。

## 4. 错误语义

`STATE_UNREADABLE`、`STATE_VERSION`、`STATE_SHAPE`、`STATE_NAME`、`STATE_DUPLICATE_MACHINE`、
`STATE_ENTITY`、`STATE_SET`、`STATE_NOTES`、`STATE_INITIAL`、`STATE_TERMINAL`、
`STATE_TERMINAL_EXIT`、`STATE_DEAD_END`、`STATE_UNREACHABLE`、`STATE_TRANSITION_STATE`、
`STATE_SELF_LOOP`、`STATE_EVENT`、`STATE_ACTOR`、`STATE_ACTOR_UNUSED`、`STATE_KIND`、
`STATE_GUARD`、`STATE_IDEMPOTENCY`、`STATE_UNTRUSTED_SUCCESS`、`STATE_NONDETERMINISTIC`、
`STATE_UNDECLARED_COMPENSATION`、`STATE_COMPENSATION_WITHOUT_EFFECT`、
`STATE_MACHINE_COVERAGE`、`STATE_DOC_MISSING`、`STATE_DOC_DRIFT`、`STATE_DOC`。

`STATE_DOC` 是失败关闭通道：模型坏到无法生成文档时，门禁必须报告而不是抛异常。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify state-machines --repo .
python3 scripts/render-states.py --check
python3 scripts/state-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 7 台机器全部通过；每个状态可达、每个非终态有出边、每个终态无出边；卡支付 created→captured 走通 |
| 重复 | 同一 `(event, token)` 重放是无操作；连续重放终态事件 5 次仍返回同一状态；不同 token 不算重放 |
| 超时 | `network.timeout` 落到 `unknown` 而非 `failed`；`unknown` 非终态；只有 `reconciliation` 能定责 |
| 拒绝 | 商户写成功状态、无幂等键、幂等键格式非法、倒退边未声明补偿、补偿边无 effects、状态不可达、非终态死角、终态仍有出边、无终态、初始状态越界、状态集与领域模型不一致、未知实体、实体无机器、机器重名、非 kebab 命名、未声明参与者、参与者未被使用、未知转移类型、无守卫、事件命名非法、目标状态不存在、自环、同一事件两个结果、机器无说明、模型不可读、文档缺失、文档被手改 |
| 失败关闭 | 模型坏到无法生成文档时给出 `STATE_DOC` 而非崩溃 |
| 解释器 | 事件不允许 / 参与者不符 / 终态之后 / 未受信参与者写成功状态（用被改坏的转移表专门触发，防止该守卫烂成死代码） |
| 运行期 | `state-smoke.py` 8 组场景 24 项断言；负向控制新增 6 个 B10 场景，共 65 个场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-states.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **本批次没有把状态机接进任何运行时服务**：平台还没有服务代码。
  这里交付的是「规范 + 门禁 + 可执行参考实现」，
  真正的持久化状态转移（带数据库唯一约束与并发测试）属于 **B12（幂等性与并发控制）**，
  数据库层的落地属于 **B13**。缺口沿用剩余风险 `RR-02`。
- **参考解释器是 Python，生产实现将是 Java**。与 B09 一样，本批次建立的是判据而非实现。
  与 B09 不同的是，B10 **还没有**生成语言中立的一致性向量——
  转移向量应当在 B11 随 API 契约一起产出，那时事件名才会被 API schema 固定下来。
  这是一个已知缺口，不要当成已完成。
- **守卫（guard）目前是自然语言**，门禁只检查它非空且足够具体，不检查它是否被代码实现。
  把守卫变成可执行谓词需要运行时上下文（金额、时间、渠道响应），属于 B12+。
- **effects 目前是自然语言**，与账本科目的绑定属于 B72/B73（账本）。
- 未建模：状态转移的**授权矩阵**（谁能调哪个 API）属于 B16–B19；
  状态变更的**审计事件格式**属于 B23。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B10/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B08 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 状态机成为「这笔钱到底怎么样了」的唯一裁决者 | 攻击者伪造客户端回跳或未验签通知，把支付推进成功状态（AC-01、NN-03） | `STATE_UNTRUSTED_SUCCESS`：成功状态只能由 `provider-event` / `reconciliation` 写入；解释器再做一次同样的判断（纵深防御），并有负向控制在运行期证明 |
| 渠道 webhook 天生会重发 | 同一事件被处理两次 → 重复捕获 / 重复退款（CTRL-003） | 每条转移必须声明幂等键；解释器按 `(event, token)` 去重，重放返回同一状态；`STATE_IDEMPOTENCY` 拦截缺失 |
| 超时会被「顺手」当成失败 | 渠道其实已扣款，平台判失败后用户重试 → 重复扣款（AC-01） | `unknown` 是一等非终态，只有 `reconciliation` 能定责；负向控制场景「timeout redefined as an outright failure」 |
| 有人想「把状态改回去」救场 | 未声明的倒退边绕过账本与审计 | `STATE_UNDECLARED_COMPENSATION` + `STATE_COMPENSATION_WITHOUT_EFFECT`（挂 NN-06 账本不可修改）：倒退必须承认自己是补偿，且必须列出效果 |
| 图与规则各说各话 | 评审看图通过，实际规则不同 | 文档由模型生成 + `STATE_DOC_DRIFT` 漂移检查 + 手改文档的负向控制场景 |
