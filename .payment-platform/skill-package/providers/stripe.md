
# Stripe 实施指南

- 卡数据通过 Stripe Elements、Payment Element、Checkout 或移动 PaymentSheet 直接进入 Stripe；平台不接触 PAN/CVV。
- 使用 PaymentIntents 表达一次支付，SetupIntents 表达未来支付授权，支持 `requires_action`、`processing`、`requires_capture` 等状态。
- 每个写请求带稳定 `Idempotency-Key`，同一键不同负载必须报冲突。
- Webhook 用原始请求体和端点 secret 验证，事件先入 Inbox，再异步处理；事件可能重复、乱序或延迟。
- Apple Pay 默认作为 Stripe 支付方式；每个生产和测试域名都需注册。
