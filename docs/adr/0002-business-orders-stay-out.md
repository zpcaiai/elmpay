# ADR-0002: 业务订单不迁入支付平台

- 状态：accepted
- 日期：2026-08-18
- 批次：B02
- 决策者：payment-platform-architecture
- 关联需求：PAY-REQ-0001, PAY-REQ-0002
- 关联控制：NN-01
- 取代：无

## 背景

多个业务项目各自拥有商品、库存与履约。若把业务订单迁入支付平台，平台将同时承担业务语义与资金语义，既扩大合规范围也让每个业务变更波及支付核心。

## 决策

平台只拥有支付事实。业务项目保留业务订单，通过 `(project_id, business_order_no)` 作为 `external_reference` 与 Payment Intent 唯一绑定。平台不接收商品、库存、履约字段。

## 后果

业务项目必须自行保证业务订单与支付意图的一致性；平台通过签名事件回传支付事实，履约判断权留在业务侧。

## 备选方案

（a）平台托管统一订单中心：拒绝，越权且放大合规与故障域；（b）平台缓存业务订单快照：拒绝，快照会变成事实上的第二事实源。

## 验证

禁止流 FF-03；`governance/module-registry.json` 禁止 `business_order*` 前缀表；`test_b00_module_registry.py`。
