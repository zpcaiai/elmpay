# 交付模式与默认部署形态

- 文档 ID：CHARTER-003
- 版本：1.0.0
- 批次：B00
- 状态：active
- 负责人：payment-platform-sre

## 1. 环境阶梯

| 环境 | 用途 | 渠道 | 数据 |
| --- | --- | --- | --- |
| local | 开发者本机，离线可重复 | 全部为模拟器 | 合成数据 |
| integration | CI 与批次证据环境 | 模拟器 + 官方沙箱 | 合成数据 |
| staging | 上线前验证、演练、UAT | 官方沙箱 | 合成 + 脱敏 |
| production | 生产 | 真实渠道 | 真实 |

`local` 与 `integration` **禁止**使用生产凭证或真实卡数据（B04）。

## 2. 部署单元与合并策略

初期允许把 `payment-core`、`merchant-config`、`risk-engine`、`ledger-service`
作为同一进程内的强模块部署，但必须满足：

1. 每个模块独占其数据表，跨模块只经由领域服务或事件访问。
2. 依赖方向单向，由 `governance/module-registry.json` 强制且 CI 校验。
3. 事件契约与 API 契约独立版本化，拆分时不需要修改调用方。

`webhook-ingress`、`webhook-delivery`、`reconciliation-service`、`worker-scheduler`
从第一天起独立部署，避免回调与批处理互相拖垮。

## 3. 发布模型

- 主干开发，短生命周期分支，所有变更经 PR 与 CODEOWNERS 复核。
- 制品不可变，带 SBOM 与签名（B109）。
- 生产采用分阶段发布与灰度（B124），回滚路径必须先演练再上线。
- 数据库迁移必须可回滚或具备前向兼容的双写/双读窗口。

## 4. 就绪定义

任何环境的“就绪”都以 `evidence/` 中可验证的证据为准，
不接受口头确认或“文档已写”作为完成依据。
