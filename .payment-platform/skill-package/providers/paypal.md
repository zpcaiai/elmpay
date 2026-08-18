
# PayPal 实施指南

- 使用 Orders v2：create → buyer approval → authorize/capture；延迟捕获和直接捕获分别建模。
- 写请求使用 `PayPal-Request-Id`；网络不确定结果先查询 Order/Authorization/Capture，不重复创建或捕获。
- Webhook 通过 PayPal 官方验证接口或官方签名验证材料确认，事件 ID 入 Inbox 去重。
- 支持退款、争议和订阅，但订单、capture、refund 和 subscription ID 必须分别存储，不混用。
- 客户端成功回调不能触发履约，必须等待服务器确认。
