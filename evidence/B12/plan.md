# B12 plan — 事件目录、Outbox 与 Inbox

Batch: 事件目录、Outbox 与 Inbox · Wave W01 · Skill `pay-events-data-architecture` · depends_on: [B10]

## 1. 范围

目标是**在至少一次传递之上得到恰好一次的业务效果**。
这不是某个中间件的功能，而是一组随时可能被悄悄改掉的设计决定，所以每一条都要能被机器检查。

1. `governance/event-catalog.json`：14 个事件、5 个消费者、信封、Outbox/Inbox 规格、
   乱序容忍策略、事件版本策略。
2. `tools/paygov/events.py`：事件目录门禁（49 条规则），含**跨事实源**检查：
   每个事件必须由 B10 的真实转移产生；每一条通往成功状态的转移必须发出事件。
3. `libs/eventing/reference/eventing.py`：**可执行参考实现**——
   同事务 Outbox、有界重试与死信、按 `(source, source_event_id)` 去重且带负载哈希的 Inbox、
   按 revision 单调应用的消费者。
4. `tools/paygov/eventgen.py` + `scripts/render-events.py`，生成
   `contracts/events/catalog.json`（语言中立）与 `docs/events/EVENT_CATALOG.md`。
5. `scripts/events-smoke.py`：**6 类故障注入**，15 项运行期断言。
6. `tools/tests/test_b12_events.py`：84 个用例。

## 2. 受影响组件

`governance/{event-catalog,ssot-registry}.json`、`tools/paygov/{events,eventgen,registry}.py`、
`libs/eventing/`、`scripts/{render-events,events-smoke}.py`、`contracts/events/`、`docs/events/`、
`tools/tests/{test_b12_events.py,support.py}`、`scripts/negative-controls.py`（扩至 82 个场景）。
无数据库变更、无服务代码。

## 3. 领域接口与数据契约

- **投递保证**：传输层 `at_least_once`，业务效果 `effectively_once`。
  任何声称传输层恰好一次的设计都被门禁拒绝——它第一次说错的时候就要用钱来买单。
- **信封**：`event_id / event_name / event_version / tenant_id / aggregate_id / revision /
  occurred_at / recorded_at / trace_id / payload`。
  **乱序以 `revision` 为准，不以 `occurred_at` 为准**：时钟会漂移，序号不会。
- **Outbox**：`outbox_event` 表，唯一键 `(aggregate_type, aggregate_id, revision)`，
  **必须与状态变更同事务**。投递方式 `poll_then_publish`，指数退避 200ms–60s，
  最多 12 次，然后进 `outbox_dead_letter`。
  先发布后提交会在崩溃时发出一条从未发生过的事件；先提交后发布只会延迟，这是可以接受的那一侧。
- **Inbox**：`inbox_event` 表，唯一键 `(source, source_event_id)` + `payload_sha256`，
  保留 720 小时。**同一 ID 带来不同 payload 是矛盾，不是重放**，必须报错而不是覆盖。
- **消费者**：每个消费者必须声明乱序容忍方式
  （`idempotent_apply` / `revision_guarded` / `buffer_and_reorder`）与具体策略。
  没说过怎么扛乱序的消费者，就是没想过这件事。
- **事件版本**：只增不改；同版本内只允许新增可选字段；新旧版本并行不少于 180 天。
- **数据分级**：每个 payload 字段必须声明分级；禁止字段清单（`pan/cvv/...`）在门禁里可执行。
- **金额**：事件里的金额必须是 `*_minor: int64` 且必须带 `currency`（NN-05）。

## 4. 错误语义

`EVENT_UNREADABLE`、`EVENT_VERSION_FIELD`、`EVENT_SHAPE`、`EVENT_DELIVERY`、`EVENT_ENVELOPE`、
`EVENT_TENANT`、`OUTBOX_NOT_TRANSACTIONAL`、`OUTBOX_SHAPE`、`OUTBOX_UNIQUE_KEY`、
`OUTBOX_DISPATCH`、`OUTBOX_DEAD_LETTER`、`INBOX_SHAPE`、`INBOX_UNIQUE_KEY`、
`INBOX_PAYLOAD_HASH`、`INBOX_RETENTION`、`INBOX_CONFLICT`、`EVENT_ORDERING`、
`EVENT_ORDERING_KEY`、`EVENT_VERSION_POLICY`、`EVENT_NAME`、`EVENT_DUPLICATE`、
`EVENT_VERSION`、`EVENT_PRODUCER`、`EVENT_AGGREGATE`、`EVENT_TRANSITION_MISSING`、
`EVENT_TRANSITION_UNKNOWN`、`EVENT_TRANSITION_AGGREGATE`、`EVENT_RETENTION`、`EVENT_FIELD`、
`EVENT_FIELD_DUPLICATE`、`EVENT_CLASSIFICATION`、`EVENT_FORBIDDEN_FIELD`、
`EVENT_FORBIDDEN_LIST`、`EVENT_MONEY_TYPE`、`EVENT_MONEY_CURRENCY`、`EVENT_NO_CONSUMER`、
`EVENT_UNCONSUMED`、`EVENT_CONSUMER_MODULE`、`EVENT_CONSUMER_DUPLICATE`、
`EVENT_CONSUMER_EMPTY`、`EVENT_ORDER_TOLERANCE`、`EVENT_SUBSCRIPTION_UNKNOWN`、
`EVENT_SUCCESS_UNPUBLISHED`、`EVENT_GENERATED_MISSING`、`EVENT_GENERATED_DRIFT`、
`EVENT_GENERATED`。

`EVENT_GENERATED` 是失败关闭通道。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify event-catalog --repo .
python3 scripts/render-events.py --check
python3 scripts/events-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 14 个事件全部有因（来自真实转移）、有消费者、有分级、有租户分区；生成物与目录一致 |
| 重复 | 同一事件投递 3 轮只产生 2 次业务效果，重复被计数；唯一键 `(aggregate_id, revision)` 挡住重试的生产者 |
| 乱序 | 逆序投递后收敛到最高 revision，落后事件被丢弃并计数；已捕获不会退回已授权 |
| 超时/故障 | 提交前崩溃 → 状态与事件都不存在；Broker 短暂不可用 → 不丢不重；Broker 永久不可用 → 进死信而非消失 |
| 矛盾 | 同一 `event_id` 带不同 payload → `PayloadConflict`，而不是静默保留第一条 |
| 拒绝 | 49 条门禁规则各有对应用例：宣称 exactly-once 传输、Outbox 脱离事务、Inbox 无负载哈希、按时间戳排序、payload 带 PAN、成功转移不发事件、死信被删掉…… |
| 失败关闭 | 目录坏到无法生成产物时给出 `EVENT_GENERATED` 而非崩溃 |
| 运行期 | `events-smoke.py` 6 类故障 15 项断言；负向控制新增 9 个 B12 场景，共 82 个场景 |

**值得单独说的一条**：`EVENT_SUCCESS_UNPUBLISHED` 在本批次第一版目录上就抓到了两个真实缺口——
`payment-attempt` 有两条通往 `succeeded` 的转移（`provider.succeeded` 与
`reconciliation.matched_success`）完全没有发出事件，账本与对账永远不会知道。
补上的两个事件是 `payment_attempt.succeeded` 与 `payment_attempt.resolved`。

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-events.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **参考实现是内存模型，不是数据库**。`Store.transact` 用「暂存后一次性提交」模拟事务原子性，
  它证明的是**设计**的正确性，不是某个 PostgreSQL 实现的正确性。
  真实的事务隔离级别、`SELECT ... FOR UPDATE SKIP LOCKED` 式的投递取数、
  分区与索引属于 **B13**，缺口沿用剩余风险 `RR-02`。
- **没有真实的消息中间件**。`Broker` 只模拟「可能失败、可能重复投递」。
  分区顺序、消费者组再平衡、背压等真实 Kafka/RocketMQ 语义**完全没有建模**。
  这会影响 `buffer_and_reorder` 消费者的可行性，属于后续基础设施批次。
- **`buffer_and_reorder` 只有声明，没有实现**。参考实现里只有 `RevisionGuardedConsumer`
  与去重（`idempotent_apply`）两种。`reconciliation-service` 声明的缓冲重排策略
  目前是**规范而非可执行代码**——这是本批次最大的一处「说了但没做」，明确记在这里。
- **事件版本演进只有策略，没有兼容性基线**。B11 给 API 做了基线快照与破坏性变更检测，
  事件目录**还没有**同等物。删字段/改类型会被人评审拦下，但不会被机器拦下。
  建议在 B13 或事件消费方真正落地时补上，做法可直接照搬 `contracts/api/openapi.baseline.json`。
- **保留期只有声明，没有清理实现**。`retention_days` 是契约，真正的归档与删除
  （含个人数据删除请求）属于 B105/B106。

## 9. 数据迁移

无。`outbox_event` 与 `inbox_event` 的建表属于 B13。

## 10. 证据与审查

`evidence/B12/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B10 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 事件成为账本与对账的唯一输入 | 一条通往成功的转移不发事件，账本永远对不上，且没人会发现 | `EVENT_SUCCESS_UNPUBLISHED`——它在本批次已经抓到两个真实缺口；负向控制场景「successful capture stops publishing an event」 |
| 崩溃时机决定发出的事件是否真实 | 先发布后提交 → 发出一条从未发生过的支付（AC-11） | `OUTBOX_NOT_TRANSACTIONAL` + 参考实现的 `crash_before_commit` 故障注入 |
| 传输层必然重复投递 | 一次重复投递变成一次重复入账（CTRL-003） | Inbox 按 `(source, source_event_id)` 去重 + `INBOX_UNIQUE_KEY`；重复投递 3 轮只产生 2 次效果 |
| 渠道可能用同一 ID 发不同内容 | 静默保留第一条会永久隐藏渠道侧的错误 | Inbox 负载哈希 + `PayloadConflict`；`INBOX_PAYLOAD_HASH` 不允许取消 |
| 时钟漂移 | 按 `occurred_at` 排序会让旧状态覆盖新状态 | `EVENT_ORDERING` 强制 `revision`；乱序测试证明已捕获不会退回已授权 |
| 事件是数据的横向扩散面 | payload 里放一个 PAN，等于同时复制进所有消费者、日志与备份（NN-02、NN-14） | `EVENT_FORBIDDEN_FIELD` + 字段分级强制 + 负向控制场景 |
| 投递不出去的事件容易被"清掉" | 静默丢弃 = 六个月后无法解释的账本差异 | `OUTBOX_DEAD_LETTER` 强制死信目的地；参考实现证明死信事件不会被标记为已发布 |
