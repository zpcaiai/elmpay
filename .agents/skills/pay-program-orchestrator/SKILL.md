---
name: pay-program-orchestrator
description: 编排完整商业级支付平台 B00-B127，解析依赖、生成下一批任务、初始化和验证证据，并执行最终生产发布门禁。
---
# 支付平台总编排器

## 适用场景

当用户要求从零构建、继续实施、评估完成度、修复缺口或认证完整商业级支付平台时使用。该技能协调 B00-B127，不代替任何批次的证据门。

## 首次执行

1. 读取 `.payment-platform/skill-package/manifest.json`。
2. 运行 `python3 .payment-platform/skill-package/scripts/verify_package.py`。
3. 在目标仓库运行 `python3 .payment-platform/skill-package/scripts/orchestrate.py status --repo .`。
4. 运行 `... ready --repo .` 获取可执行批次；初始状态只能出现 B00。
5. 对每个 ready 批次运行 `... prompt Bxx --repo .`，按照对应技能和批次文件实施。

## 编排原则

- 不跳过依赖；不把文档声称当作代码或运行证据。
- 可并行执行互不依赖批次，但每个批次单独提交、单独证据、单独审查。
- 资金、身份、密钥、路由、退款、账本和生产变更必须 fail closed。
- 每完成一个批次立即运行 `... validate Bxx --repo .`，失败则修复，不继续堆叠。
- B127 之前运行 `verify_release.py`；任何缺口都阻止生产认证。

## 任务分派

读取 `manifest.json` 中批次的 `skill` 字段，调用对应 `.agents/skills/<skill>/SKILL.md` 或 `.claude/skills/<skill>/SKILL.md`。详细要求位于 `batches/Bxx.md`，禁止仅根据技能简介实现。

## 必须报告

每轮输出：已完成批次、当前 ready、阻塞项、风险变化、证据路径、下一批次提示。不得宣称“生产就绪”，除非 B127 的验证脚本和独立评审同时通过。
