# elmpay — 企业级统一支付平台

多项目订单接入 + 统一支付编排。业务订单留在各业务系统，本平台只拥有**支付事实**：
Payment Intent / Attempt、渠道交互、复式账本、对账结果与风控证据。

优先渠道：微信支付 APIv3、支付宝证书模式；其后 Stripe、PayPal、Apple Pay（托管字段 / 令牌化）。

> **当前实现边界（2026-08-30）**：仓库已包含生产模式的 edge gateway、托管收银台、
> Admin 控制面、独立风控服务、Webhook 处理器与调度/事件/账本/对账 worker 源码，
> 并为微信、支付宝、Stripe、PayPal 和 Apple Pay-via-PSP 提供真实协议适配与严格凭证
> 边界。仓库代码和本地测试仍不能替代渠道官方认证、独立人工评审、生产集群/多地域
> 演练、PCI/UAT/渗透测试或商户 shadow/canary 验收；认证状态仍为
> **`0/128 NOT_CERTIFIED`**。

## 交付方式

本仓库按 `.payment-platform/skill-package` 定义的 **B00–B127 / W00–W15** 批次 DAG 推进。
每个批次必须自带代码、测试、运行证据、安全证据与独立审查，缺一即 `blocked`/`failed`。

```bash
# 校验技能包与已安装镜像
make skills-verify
# 当前进度（包含本仓库额外的证据门禁）
python3 scripts/batch.py status
# 可执行批次
python3 scripts/batch.py ready
# 校验某批次证据
python3 scripts/batch.py validate B00
# 对照随技能包交付的原始编排器，防止本地门禁放宽
python3 scripts/batch.py crosscheck
```

`.ai/rebaseline.py` 是仓库内唯一受支持的证据续跑入口。它把状态绑定到仓库真实路径、
当前提交、批次清单与命令谱摘要，拒绝复用过期状态；先用 `status` 查看，再用
`migrate-shards` 做一次命令分片迁移，最后反复执行有界的 `resume` 启动窗口。
状态只写入被 Git 忽略的 `.ai/.state/`，不会伪装成完成证据。命令全部成功后仍必须由
配置中的独立人类审查者提交与当前代码、命令谱和产物摘要绑定的
`evidence/<batch>/review.json`；缺失时续跑会报告 `review-blocked`，不会写 completion。

```bash
python3 .ai/rebaseline.py --help
python3 .ai/rebaseline.py status --from B00 --to B33
python3 .ai/rebaseline.py migrate-shards --from B00 --to B33 --shards 4 --dry-run
python3 .ai/rebaseline.py resume --from B00 --to B33 --launch-window-seconds 300 --dry-run
```

启动窗口只限制何时再启动下一条事务化命令；已启动的切片会安全完成，不会在写入中途被强杀。

## 治理工具链

`tools/paygov` 是**零第三方依赖**（仅 Python 3.10+ 标准库）的仓库治理工具，
用于校验章程、项目配置、不可妥协红线、模块边界、需求、威胁模型、工具链目录、
开发平台、CI 门禁、证据与追踪矩阵。

```bash
make verify        # 全量治理校验 + 测试
make test          # 仅测试
make governance    # 仅校验
make ai-status     # 查看证据续跑状态
make test-matrix   # 执行 B00-B127 SOTA 矩阵（外部证据保持 BLOCKED）
```

完整测试策略与可执行场景见 [`docs/testing/SOTA_TEST_PLAN.md`](docs/testing/SOTA_TEST_PLAN.md)，
机器可读矩阵见 `testing/test-matrix.json`。矩阵覆盖完整不代表生产认证；当前认证仍保持
`0/128 NOT_CERTIFIED`，且运行器不会写入 `evidence/`。

## 布局

| 目录 | 内容 |
| --- | --- |
| `apps/` | 可运行的 edge-gateway、checkout-web、admin-web 生产入口与测试 |
| `services/` | payment-core、risk-engine、webhook、worker、ledger、reconciliation 等领域/运行时 |
| `connectors/` | 微信、支付宝、Stripe、PayPal、Apple Pay-via-PSP 协议适配器与契约测试 |
| `libs/` | money、domain-events、idempotency、audit、security、observability |
| `contracts/` | openapi、asyncapi、protobuf |
| `platform/` | terraform、kubernetes、policies、dev |
| `governance/` | 机器可读的单一事实源（SSOT） |
| `docs/` | 章程、ADR、追踪矩阵 |
| `tools/` | 治理工具与测试 |
| `evidence/` | 批次证据与完成文件 |

## 红线

见 `docs/charter/PROGRAM_CHARTER.md` 与 `governance/non-negotiables.json`。
其中最重要的三条：**不以客户端结果定责、不托管原始卡数据、所有副作用幂等**。
