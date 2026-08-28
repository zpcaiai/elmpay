<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/event-catalog.json
     Regenerate with: python3 scripts/render-events.py -->

# 事件目录、Outbox 与 Inbox（B12）

本文由 `governance/event-catalog.json` 生成。事件与状态机转移的绑定由门禁强制一致（`EVENT_TRANSITION_UNKNOWN`、`EVENT_SUCCESS_UNPUBLISHED`）。

## 投递保证

- 传输层：`at_least_once`
- 业务效果：`effectively_once`
- 传输层只承诺至少一次。恰好一次的**业务效果**由 inbox 去重 + 消费方幂等达成，而不是靠一个声称 exactly-once 的中间件。任何声称传输层恰好一次的设计都要被拒绝。

## 信封

必备字段：`event_id`、`event_name`、`event_version`、`tenant_id`、`aggregate_id`、`revision`、`occurred_at`、`recorded_at`、`trace_id`、`payload`

信封字段固定；payload 里的内容按事件目录逐条声明。revision 单调递增，是乱序容忍的唯一依据——occurred_at 会因时钟漂移倒退。

## Outbox

- 表：`outbox_event`（属于 `payment-core`）
- 唯一键：`aggregate_type`、`aggregate_id`、`revision`
- 与状态变更同事务：是
- 投递：poll_then_publish，批量 200，exponential 退避 200–60000ms，最多 12 次，死信表 `outbox_dead_letter`

状态变更与 outbox 写入必须在同一个数据库事务里。先发布后提交会在崩溃时发出一条从未发生过的事件；先提交后发布只会导致延迟发布，这是可以接受的那一侧。

## Inbox

- 表：`provider_webhook_inbox`，唯一键 `source`、`source_event_id`
- 负载哈希字段：`payload_sha256`，冲突错误 `idempotency_key_reuse`，保留 720 小时

同一 (source, source_event_id) 只处理一次；如果同一 ID 带来了不同的 payload 哈希，那不是重放而是矛盾，必须报错而不是覆盖。

## 乱序容忍

排序键 `aggregate_id`，序号 `revision`，缓冲空洞上限 100。

乱序容忍以 revision 为准，不以 occurred_at 为准：时钟会漂移，序号不会。

## 事件

| 事件 | 版本 | 生产者 | 聚合 | 由哪条转移产生 | 消费者 | 保留天数 |
| --- | --- | --- | --- | --- | --- | --- |
| `payment_intent.authorized` | v1 | `payment-core` | PaymentIntent | `payment-intent` / `provider.authorized` | `ledger-service`、`risk-engine`、`webhook-delivery` | 2555 |
| `payment_intent.captured` | v1 | `payment-core` | PaymentIntent | `payment-intent` / `provider.captured` | `ledger-service`、`reconciliation-service`、`webhook-delivery` | 2555 |
| `payment_intent.capture_closed` | v1 | `payment-core` | PaymentIntent | `payment-intent` / `provider.authorization_closed` | `ledger-service`、`reconciliation-service`、`webhook-delivery` | 2555 |
| `payment_intent.failed` | v1 | `payment-core` | PaymentIntent | `payment-intent` / `provider.declined` | `risk-engine`、`webhook-delivery` | 2555 |
| `payment_intent.canceled` | v1 | `payment-core` | PaymentIntent | `payment-intent` / `merchant.cancel` | `webhook-delivery` | 2555 |
| `payment_intent.voided` | v1 | `payment-core` | PaymentIntent | `payment-intent` / `merchant.void` | `ledger-service`、`webhook-delivery` | 2555 |
| `payment_attempt.unresolved` | v1 | `payment-core` | PaymentAttempt | `payment-attempt` / `network.timeout` | `reconciliation-service`、`worker-scheduler` | 2555 |
| `refund.succeeded` | v1 | `payment-core` | Refund | `refund` / `provider.refunded` | `ledger-service`、`reconciliation-service`、`webhook-delivery` | 2555 |
| `refund.failed` | v1 | `payment-core` | Refund | `refund` / `provider.refund_failed` | `webhook-delivery` | 2555 |
| `dispute.opened` | v1 | `payment-core` | Dispute | `dispute` / `provider.evidence_requested` | `ledger-service`、`risk-engine`、`webhook-delivery` | 2555 |
| `dispute.lost` | v1 | `payment-core` | Dispute | `dispute` / `provider.dispute_lost` | `ledger-service`、`risk-engine`、`webhook-delivery` | 2555 |
| `subscription.past_due` | v1 | `payment-core` | Subscription | `subscription` / `billing.charge_failed` | `worker-scheduler`、`webhook-delivery` | 2555 |
| `reconciliation.exception_opened` | v1 | `reconciliation-service` | ReconciliationException | `reconciliation-run` / `recon.matching_finished` | `risk-engine`、`webhook-delivery` | 2555 |
| `payment_attempt.succeeded` | v1 | `payment-core` | PaymentAttempt | `payment-attempt` / `provider.succeeded` | `ledger-service`、`reconciliation-service`、`webhook-delivery` | 2555 |
| `payment_attempt.resolved` | v1 | `reconciliation-service` | PaymentAttempt | `payment-attempt` / `reconciliation.matched_success` | `ledger-service`、`risk-engine`、`webhook-delivery` | 2555 |

- **`payment_intent.authorized`**：授权只占额度不动账；账本记的是授权科目而不是收入。
- **`payment_intent.captured`**：这是唯一代表「钱真的到了」的事件；下游的收入确认以它为准。
- **`payment_intent.capture_closed`**：渠道确认释放部分捕获后的剩余授权；实际已捕获金额仍是最终支付事实。
- **`payment_intent.failed`**：失败是终态；重试必须开新的 attempt，因此本事件不携带重试指引。
- **`payment_intent.voided`**：撤销授权是补偿动作，账本要冲销授权科目，所以 ledger-service 必须订阅。
- **`payment_attempt.unresolved`**：超时不是失败。本事件的唯一目的是把定责责任交给对账与主动查询。
- **`refund.failed`**：退款失败意味着资金未离开，允许发起新的退款单；不要在下游做自动重试。
- **`dispute.opened`**：争议开启即冻结资金，所以账本必须订阅而不是等裁定结果。
- **`reconciliation.exception_opened`**：对账跑完不代表全对上，只代表全部有交代；未匹配项在这里变成可追责对象。
- **`payment_attempt.succeeded`**：attempt 层的定责结果。它与 payment_intent.captured 是两件事：attempt 说的是「这次尝试成功了」，intent 说的是「这笔钱最终到账了」。
- **`payment_attempt.resolved`**：把一个 unknown 定责为成功。这条事件的存在本身就是 AC-01 的对策：超时不会被静默判失败，它会一直挂在 unknown 上，直到有人发出这条事件。

## 消费者与乱序策略

| 模块 | 乱序容忍 | 策略 | 订阅数 |
| --- | --- | --- | --- |
| `ledger-service` | `revision_guarded` | 按 (aggregate_id, revision) 单调应用；revision 不大于已应用值的事件直接丢弃并记数。 | 10 |
| `risk-engine` | `idempotent_apply` | 风控特征写入是幂等 upsert，重复或乱序不改变结果。 | 6 |
| `reconciliation-service` | `buffer_and_reorder` | 按 aggregate 缓冲最多 revision_gap_limit 个空洞，超时后升级为对账例外。 | 5 |
| `webhook-delivery` | `idempotent_apply` | 对外投递按 event_id 去重；乱序由订阅方自行处理，我们只保证不丢不重发同一 event_id。 | 14 |
| `worker-scheduler` | `idempotent_apply` | 调度任务按 (aggregate_id, period) 唯一，重复事件不会排出第二个任务。 | 2 |

共 15 个事件、5 个消费者。
