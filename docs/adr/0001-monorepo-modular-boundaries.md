# ADR-0001: 单仓多模块，先合并部署后可拆分

- 状态：accepted
- 日期：2026-08-18
- 批次：B02
- 决策者：payment-platform-architecture
- 关联需求：PAY-REQ-0010, PAY-REQ-0040
- 关联控制：NN-01
- 取代：无

## 背景

平台需要在早期快速打通微信/支付宝主链路，同时不能在规模扩大后被单体锁死。完全微服务化会在需求尚未稳定时付出高昂的分布式事务与运维代价。

## 决策

采用单仓多模块。`payment-core`、`merchant-config`、`risk-engine`、`ledger-service` 允许合并进程部署；`webhook-ingress`、`webhook-delivery`、`reconciliation-service`、`worker-scheduler` 从第一天独立部署。模块的表所有权、事件边界与依赖方向由 `governance/module-registry.json` 声明并由 CI 强制。

## 后果

拆分成本被前置为一次性的边界约束；违反边界会在 CI 失败而不是在生产事故中暴露。代价是早期开发要接受额外的模块化纪律。

## 备选方案

（a）一开始就全微服务：拒绝，早期需求变化会导致跨服务契约反复破坏；（b）纯单体不设边界：拒绝，后期无法拆分且租户隔离难以论证。

## 验证

`tools/tests/test_b00_module_registry.py` 强制层级、无环、表独占；连接器不得触达服务层。
