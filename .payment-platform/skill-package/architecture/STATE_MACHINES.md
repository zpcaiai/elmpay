
# 状态机与最终性

## Payment Intent

`REQUIRES_PAYMENT_METHOD → REQUIRES_CONFIRMATION → PROCESSING → SUCCEEDED`

可分支到 `REQUIRES_ACTION`、`REQUIRES_CAPTURE`、`CANCELED`、`FAILED`。`SUCCEEDED` 不允许回退；退款通过 Refund 状态和账本反向事实表达。

## Attempt

`CREATED → SENT → ACKNOWLEDGED → PENDING_EXTERNAL → SUCCEEDED | FAILED | UNKNOWN`

`UNKNOWN` 必须主动查询渠道，禁止盲目重发可能扣款的请求。每个 attempt 只能对应一个 provider request id 和一个幂等键。

## Refund

`REQUESTED → APPROVAL_PENDING | PROCESSING → SUCCEEDED | PARTIALLY_SUCCEEDED | FAILED | UNKNOWN`

退款总额不得超过已捕获金额减去已成功退款；并发下由数据库约束和序列化检查保证。

## Webhook

`RECEIVED → VERIFIED → STORED → PROCESSED → ACKED_INTERNAL`。验签失败进入隔离，不得触发支付状态或履约。

## Reconciliation

`INGESTED → MATCHED | EXCEPTION → INVESTIGATING → RESOLVED | ACCEPTED_DIFFERENCE`，所有人工调整需双人审批和反向分录。
