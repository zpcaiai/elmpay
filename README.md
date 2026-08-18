# elmpay — 企业级统一支付平台

多项目订单接入 + 统一支付编排。业务订单留在各业务系统，本平台只拥有**支付事实**：
Payment Intent / Attempt、渠道交互、复式账本、对账结果与风控证据。

优先渠道：微信支付 APIv3、支付宝证书模式；其后 Stripe、PayPal、Apple Pay（托管字段 / 令牌化）。

## 交付方式

本仓库按 `.payment-platform/skill-package` 定义的 **B00–B127 / W00–W15** 批次 DAG 推进。
每个批次必须自带代码、测试、运行证据、安全证据与独立审查，缺一即 `blocked`/`failed`。

```bash
# 当前进度
python3 .payment-platform/skill-package/scripts/orchestrate.py status --repo .
# 可执行批次
python3 .payment-platform/skill-package/scripts/orchestrate.py ready --repo .
# 校验某批次证据
python3 .payment-platform/skill-package/scripts/orchestrate.py validate B00 --repo .
```

## 治理工具链

`tools/paygov` 是**零第三方依赖**（仅 Python 3.10+ 标准库）的仓库治理工具，
用于校验章程、项目配置、不可妥协红线、模块边界、需求、威胁模型、工具链目录、
开发平台、CI 门禁、证据与追踪矩阵。

```bash
make verify        # 全量治理校验 + 测试
make test          # 仅测试
make governance    # 仅校验
```

## 布局

| 目录 | 内容 |
| --- | --- |
| `apps/` | edge-gateway、checkout-web、admin-web |
| `services/` | payment-core、webhook-ingress/delivery、merchant-config、risk-engine、ledger-service、reconciliation-service、worker-scheduler |
| `connectors/` | wechat-pay、alipay、stripe、paypal、apple-pay |
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
