<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/payment-attempt.json
     Regenerate with: python3 scripts/render-attempt.py -->

# 支付尝试与渠道交易（B33）

**每一次渠道调用都是一个新的、不可变的 attempt**，永远不复用上一条。把重试写回原来那一行，会抹掉「我们当时到底发了什么、什么时候发的」——而那正是事后唯一能回答「第一次调用到底有没有到渠道」的东西。由此派生的第一条也是本批次最重要的一条：**超时不是失败**。超时的结果是**未知**；把未知当成失败去重试，就是重复扣款的标准生成方式。另外两条：**未解决的未知会挡住下一次尝试**——必须先主动查询或对账把它落定；**只存请求摘要不存请求本身**——我们要能证明发了什么，但不能因此保留卡号。

## attempt

- 不可变：是；一次渠道调用一条：是
- 重试复用旧记录：**禁止**
- 每笔意图内序号单调：是
- 必需字段：`tenant_id`、`intent_id`、`provider`、`sequence`、`request_digest`、`response_digest`、`provider_request_id`、`provider_transaction_id`、`outcome_class`、`provider_code_namespace`、`provider_code`、`started_at`、`finished_at`

attempt 一旦写入终态就不可修改。重试开新的一条，序号单调递增——序号是事后重建时间线唯一可靠的东西，时间戳会因为时钟漂移骗人。

## 租户边界与并发

- tenant_id 必填：是；查询键：`tenant_id` + `intent_id`
- 外部 ID 不作为内部 ID：是

所有查询、状态变化和去重都显式携带 tenant_id；同名 intent_id 在不同租户下互不相见。attempt_id 与渠道请求号独立生成，不把租户 ID、intent_id 或渠道 ID 拼成内部主键。

- start 原子化：是；冲突键：`tenant_id` + `intent_id`
- 并发重复：`reject_without_provider_call`

同一 tenant_id + intent_id 的并发 start 必须原子化：只有一个调用创建 attempt，其他调用在触达渠道前被拒绝。参考实现使用进程内锁；生产实现必须换成数据库唯一约束或等价的分布式原子机制。

## 参考实现边界

- 进程内锁：是；持久化：**否**；数据库唯一约束：**否**
- 运行时审计写入：**否**；生产就绪：**否**
- B32 replacement confirmation 已接通：**否**

当前 Python 代码只是不变量参考实现：并发保护仅覆盖单进程，记录不持久化，也没有把 attempt 事件写入 B23 审计存储。replacement_request 只建模 B33 attempt 规则，尚未接入 B32 Intents.confirm，也没有验证客户动作主体；因此不能声称更换资金源端到端可用、生产就绪或 B33 完成门已通过。

## 请求记录

- 存摘要不存报文：是；算法：`sha256`
- 脱敏字段：`pan`、`cvv`、`credential`、`token`
- 可重放：**否**

存摘要不存报文：我们需要证明「发出去的就是这一份」，但不需要为此把卡号留在库里。摘要也**不可用于重放**——一个能重放的请求记录就是一个能再扣一次钱的按钮。

## 响应记录

- 存规范化摘要不存原始响应：是；算法：`sha256`
- 保留的证据字段：`provider_code`、`provider_request_id`、`provider_transaction_id`、`outcome_class`、`provider_code_namespace`、`response_digest`
- 禁止进入记录：`raw_response`、`response_body`、`headers`、`authorization`、`credential`、`token`、`pan`、`cvv`
- 可重放：**否**

渠道响应只保留规范化的结果码、请求号、交易号、结果分类及其 SHA-256 摘要，不接收或保存原始响应体、响应头、凭证或令牌。这样既能重建渠道调用时间线，又不会把 attempt 表变成第二份敏感报文仓库。

## 结果分类

| 分类 | attempt 终态 | 落定 intent | 同请求可重试 | 需落定 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `succeeded` | 是 | 是 | 否 | 否 | 渠道明确成功。 |
| `failed_final` | 是 | 否 | 否 | 否 | 渠道明确拒绝当前请求。**本次 attempt 终态且同一请求不可重试**，但它本身不把 PaymentIntent 永久落为失败；付款人更换资金源或重新授权后，可以用新的幂等键和新的 attempt 再试。 |
| `failed_retryable` | 是 | 否 | 是 | 否 | 渠道明确表示「现在不行、稍后再来」（限流、临时不可用）。本次 attempt 已终结，但同一请求可按退避策略开新 attempt 并复用幂等键。 |
| `unknown` | 否 | 否 | 否 | 是 | **超时、连接中断、无法解析的响应全部落在这里**。未知不是失败：钱可能已经扣了。必须先查询或对账落定，才允许下一次尝试。 |

## 超时

- 归类为：**`unknown`**
- 落定前允许重试：**否**
- 落定方式：`provider_query`、`reconciliation_file`
- 最长落定时限：24 小时

超时归类为未知，这条规则比它看起来重要得多：把超时当失败并立即重试，是支付系统里最常见的重复扣款成因。

## 重试

- 必须开新 attempt：是；复用幂等键：是
- 仅限可重试分类：是；上限：3 次
- 更换资金源仅允许在：`failed_final`
- 更换请求必须使用新幂等键：是；必须由客户动作触发：是
- 退避：1s、5s、25s

同一请求的传输/临时错误重试复用原幂等键，但必须开新 attempt。更换资金源或重新授权不是同一请求重试：它必须由明确的客户动作触发，并使用新的幂等键。两类路径不得混用。

## 渠道错误分类表

| 渠道 | 码命名空间 | 渠道码 | 分类 | 说明 |
| --- | --- | --- | --- | --- |
| `alipay` | `alipay.sub_code` | `ACQ.BUYER_BALANCE_NOT_ENOUGH` | `failed_final` | 余额不足，明确拒绝。 |
| `alipay` | `alipay.sub_code` | `ACQ.SYSTEM_ERROR` | `unknown` | 支付宝系统异常，结果未知，必须主动查询后再决定。 |
| `apple_pay` | `adapter.normalized` | `DECRYPT_FAILED` | `failed_final` | elmpay Apple Pay/PSP 适配器归一化码，不声称是 Apple 官方错误码；令牌解密失败时同一令牌不可重试。 |
| `paypal` | `paypal.details.issue` | `INSTRUMENT_DECLINED` | `failed_final` | PayPal Orders v2 的 details.issue：当前资金源对应的请求已明确失败，不可原样自动重试；付款人选择其他资金源后，按 replacement request 使用新幂等键重试，因此不会永久落定 PaymentIntent。 |
| `stripe` | `stripe.error.code` | `card_declined` | `failed_final` | 明确拒绝。 |
| `stripe` | `stripe.error.code` | `processing_error` | `failed_retryable` | 渠道内部临时错误。 |
| `stripe` | `stripe.error.code` | `rate_limit` | `failed_retryable` | 被限流：稍后重试会成功，因此归入可重试而不是失败。 |
| `wechat` | `wechat.api_v3.code` | `ORDERPAID` | `succeeded` | 「订单已支付」是成功而不是错误——把它当错误会触发一次不必要的退款。 |
| `wechat` | `wechat.api_v3.code` | `SYSTEMERROR` | `unknown` | 渠道明说结果未知，必须查询。 |

**未登记的渠道码一律归入 `unknown`**——没见过的码，按定义就是不知道结果。

## 最终性

- 终态 attempt 不可修改：是
- 意图结果取自终态 attempt：是
- 后到的矛盾事件：开对账项 是；覆盖 **否**

终态 attempt 不可修改。只有明确标记 settles_intent 的 attempt 决定 PaymentIntent；当前分类中成功会落定意图，失败只结束该次请求。之后到达的矛盾渠道事件开对账项而不覆盖历史。

## 生命周期

- 来源：`governance/state-machines.json#payment-attempt`（B10 定义，此处引用）
- 状态：`initiated`、`pending`、`succeeded`、`failed`、`unknown`
- 初始：`initiated`；终态：`succeeded`、`failed`
- 成功态：`succeeded`

状态机在 B10 定义，此处引用。注意 `unknown` **不是终态**：它必须被落定。

审计事件类别：`money.movement`（见 B23）。
