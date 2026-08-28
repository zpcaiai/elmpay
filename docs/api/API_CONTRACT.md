<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/api-contract.json
     Regenerate with: python3 scripts/render-api.py -->

# API 规范、错误与兼容模型（B11）

本文由 `governance/api-contract.json` 生成。操作与状态机转移的绑定由门禁强制一致（`API_TRANSITION_KEY_MISMATCH`、`API_TRANSITION_ACTOR`）。

## 版本与弃用

- 版本方式：路径大版本（当前 `v1`）
- 策略：同一大版本内只允许向后兼容的加法；破坏性变更必须开新的大版本。
- 旧大版本并行支持：不少于 12 个月
- 弃用：`Sunset` 头 + 不少于 180 天预告

## 幂等、分页、追踪与金额

- 幂等：`Idempotency-Key`，最短保留 168 小时；所有写操作必须携带幂等键；同键不同体必须冲突而不是覆盖。
- 分页：只允许游标分页。偏移分页在持续写入的支付数据上会漏记录或重复记录，这在对账场景里等于账不平。（禁止参数：`offset`, `page`, `page_number`, `skip`）
- 追踪：必须携带 `traceparent`, `X-Request-Id`；trace 与日志中不得出现凭据、卡号、完整支付令牌或不必要个人信息（NN-14）。
- 金额：API 上的金额一律是 {amount_minor:int64, currency:char(3)}；不存在小数金额字段（NN-05）。

## 错误目录

| 错误码 | HTTP | 可重试 | 类别 | 含义 | 应对 |
| --- | --- | --- | --- | --- | --- |
| `amount_below_minimum` | 422 | 否 | money | 金额低于该币种的最小可交易金额。 | 提高金额；金额单位是最小货币单位整数 |
| `currency_not_supported` | 422 | 否 | money | 该币种不在受支持列表内。 | 查询受支持币种列表后重试 |
| `idempotency_key_reuse` | 409 | 否 | idempotency | 同一幂等键曾用于不同的请求体。 | 换一个幂等键，或使用与首次完全相同的请求体重放 |
| `internal_error` | 500 | 是 | server | 服务内部错误。 | 按指数退避重试；如持续发生请携带 trace_id 联系支持 |
| `invalid_request` | 400 | 否 | client | 请求不符合契约；请检查字段类型与必填项。 | 按 OpenAPI 契约修正请求后重试 |
| `permission_denied` | 403 | 否 | auth | 当前主体无权执行该操作。 | 联系租户管理员申请对应角色 |
| `provider_event_replayed` | 200 | 否 | webhook | 该渠道事件此前已处理，本次为重放。 | 无需处理；这是正常的重发去重结果 |
| `provider_signature_invalid` | 401 | 否 | webhook | 回调签名校验失败。 | 不要重试；检查签名密钥与时间戳容忍窗口 |
| `provider_timeout` | 504 | 是 | provider | 上游渠道超时，结果未定。 | **不要**当作失败；用同一幂等键重试或轮询对象状态 |
| `provider_unavailable` | 502 | 是 | provider | 上游渠道暂时不可用。 | 按指数退避重试；不要重新生成幂等键 |
| `rate_limited` | 429 | 是 | throttle | 请求过于频繁。 | 读取 Retry-After 并退避重试 |
| `resource_not_found` | 404 | 否 | client | 对象不存在，或不属于当前租户。 | 确认对象 ID；注意本接口不区分不存在与无权访问 |
| `state_transition_not_allowed` | 409 | 否 | state | 对象当前状态不允许该操作。 | 先读取对象当前状态；不要假设本地缓存的状态仍然有效 |
| `tenant_mismatch` | 403 | 否 | auth | 该对象不属于当前租户。 | 确认使用了正确租户的密钥；不要跨租户引用对象 ID |
| `unauthenticated` | 401 | 否 | auth | 凭据缺失或无效。 | 使用有效的 API 密钥重新签名请求 |

## 操作

| 操作 | 方法 | 路径 | 调用方 | 认证 | 幂等键作用域 | 驱动的状态转移 |
| --- | --- | --- | --- | --- | --- | --- |
| `create_payment_intent` | POST | `/v1/payment_intents` | `merchant` | `api_key` | `idempotency_key` | — |
| `get_payment_intent` | GET | `/v1/payment_intents/{payment_intent_id}` | `merchant` | `api_key` | — | — |
| `list_payment_intents` | GET | `/v1/payment_intents` | `merchant` | `api_key` | — | — |
| `capture_payment_intent` | POST | `/v1/payment_intents/{payment_intent_id}/capture` | `merchant` | `api_key` | `idempotency_key` | — |
| `cancel_payment_intent` | POST | `/v1/payment_intents/{payment_intent_id}/cancel` | `merchant` | `api_key` | `idempotency_key` | `payment-intent` / `merchant.cancel` |
| `void_payment_intent` | POST | `/v1/payment_intents/{payment_intent_id}/void` | `merchant` | `api_key` | `idempotency_key` | `payment-intent` / `merchant.void` |
| `close_payment_intent` | POST | `/v1/payment_intents/{payment_intent_id}/close` | `merchant` | `api_key` | `idempotency_key` | — |
| `create_refund` | POST | `/v1/refunds` | `merchant` | `api_key` | `idempotency_key` | — |
| `cancel_refund` | POST | `/v1/refunds/{refund_id}/cancel` | `merchant` | `api_key` | `idempotency_key` | `refund` / `merchant.cancel_refund` |
| `get_refund` | GET | `/v1/refunds/{refund_id}` | `merchant` | `api_key` | — | — |
| `list_refunds` | GET | `/v1/refunds` | `merchant` | `api_key` | — | — |
| `get_dispute` | GET | `/v1/disputes/{dispute_id}` | `merchant` | `api_key` | — | — |
| `list_disputes` | GET | `/v1/disputes` | `merchant` | `api_key` | — | — |
| `submit_dispute_evidence` | POST | `/v1/disputes/{dispute_id}/evidence` | `merchant` | `api_key` | `dispute_id+evidence_revision` | `dispute` / `merchant.evidence_submitted` |
| `cancel_subscription` | POST | `/v1/subscriptions/{subscription_id}/cancel` | `customer` | `api_key` | `idempotency_key` | `subscription` / `customer.cancel` |
| `receive_provider_event` | POST | `/v1/webhooks/providers/{provider}` | `provider-event` | `provider_signature` | `provider_event_id` | — |

共 16 个操作（其中 10 个写操作，全部要求幂等键）、15 个错误码。
