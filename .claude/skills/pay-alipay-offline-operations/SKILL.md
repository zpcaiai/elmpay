---
name: pay-alipay-offline-operations
description: 实现并验证 B46–B47：支付宝当面付与小程序支付与支付宝退款、关闭、查询、账单与通知。用于支付平台对应领域的代码、测试、证据和生产门禁。
---
# 支付宝当面付与小程序支付 / 支付宝退款、关闭、查询、账单与通知

## 何时使用

当任务涉及 B46 或 B47，或用户要求实现、审查、修复与本技能领域相关的支付平台能力时使用。

## 权威输入

- `.payment-platform/skill-package/batches/B46.md`
- `.payment-platform/skill-package/batches/B47.md`
- `.payment-platform/skill-package/policies/non-negotiables.md`
- `.payment-platform/skill-package/architecture/REFERENCE_ARCHITECTURE.md`
- `.payment-platform/skill-package/security/THREAT_MODEL.md`
- `.payment-platform/skill-package/contracts/`

## 工作流

1. 运行编排器确认批次 ready，读取依赖完成证据和当前仓库状态。
2. 将批次目标分解为可审查的代码、迁移、配置、契约、测试、运行证据和文档。
3. 先写或更新失败测试与不变量，再实现最小安全变更；每个外部副作用必须幂等。
4. 执行批次文件要求的正常、错误、并发、故障、安全和恢复测试。
5. 初始化并填充 `evidence/B46/`，生成完成文件，运行验证器。
6. 发现已有实现与不变量冲突时，停止扩展并先修复根因及回归测试。

## 代码要求

- 使用明确领域类型，金额不得使用浮点；外部 ID、内部 ID、租户 ID 不得混用。
- 所有外部请求设置超时、可分类错误、有限重试、熔断和可观察性。
- Webhook 与消息处理采用持久 inbox；外发事件采用 outbox；不声称网络层恰好一次。
- 任何高权限操作记录主体、理由、工单、前后值和关联追踪，并满足职责分离。
- 不复制渠道 SDK 的密码学实现；优先使用官方 SDK，并用契约测试锁定行为。

## 完成判定

只接受批次文件定义的证据。缺失证据、占位实现、跳过关键测试、生产凭证进入测试、无法恢复或无法解释资金差异时必须失败。
