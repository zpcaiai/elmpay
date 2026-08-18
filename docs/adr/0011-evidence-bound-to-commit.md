# ADR-0011: 证据绑定提交并支持重新基线

- 状态：accepted
- 日期：2026-08-18
- 批次：B02
- 决策者：payment-platform-security payment-platform-platform-eng
- 关联需求：PAY-REQ-0049
- 关联控制：NN-12, CTRL-020
- 取代：无

## 背景

批次门禁按产物摘要校验完成文件。后续批次会合法修改早期批次的共享产物，若不允许重新出证据，要么证据静默失真，要么共享代码在 B00 之后被冻结。

## 决策

完成文件的每个字段都由仓库状态重新计算；`scripts/finish-batch.py` 与 `scripts/rebaseline.py` 按依赖顺序重新产生证据，且重新基线必须重新跑全量测试、治理门禁与运行期负向控制。

## 后果

每次跨批次修改共享代码都要付出一次重新基线的运行成本；换来的是证据与代码始终一致。

## 备选方案

（a）冻结早期产物：拒绝，实际不可行；（b）只在最终发布前统一出证据：拒绝，等于放弃逐批次门禁。

## 验证

`docs/EVIDENCE.md`；`scripts/rebaseline.py` 的真实运行记录在各批次 `commands.ndjson` 中。
