<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/requirements.json + governance/service-boundaries.json + docs/adr/
     Regenerate with: python3 scripts/render-docs.py -->

# 双向追踪矩阵（B07）

需求 53 条 · 能力 18 项 · ADR 13 条 · 红线 15 条 · 控制 20 条。

批次证据到控制的映射不在本文档中——它随证据变化，放进受哈希固定的文档会造成
“完成一个批次即让该批次失效”的循环。见 `evidence/*/runtime/trace-graph.json`。

## 需求 → 能力 → 模块 → 控制 → 验证批次 → ADR

| 需求 | 标题 | 能力 | 责任模块 | 控制 | 验证批次 | ADR |
| --- | --- | --- | --- | --- | --- | --- |
| PAY-REQ-0001 | 多项目 Payment Intent 接入 | CAP-01 | `payment-core` | NN-01 | B15 B32 B120 | 0002 |
| PAY-REQ-0002 | 外部引用唯一绑定 | CAP-01 | `payment-core` | NN-04 CTRL-003 | B32 B36 | 0002 |
| PAY-REQ-0003 | 创建幂等键必填 | CAP-01 | `idempotency` | NN-04 CTRL-003 | B36 B115 | 0005 |
| PAY-REQ-0004 | 项目注册与凭证签发 | CAP-01 | `merchant-config` | NN-09 CTRL-016 | B24 B30 | — |
| PAY-REQ-0005 | 支付事实签名投递 | CAP-02 | `webhook-delivery` | NN-03 CTRL-002 | B38 B114 | — |
| PAY-REQ-0006 | 回调地址白名单 | CAP-02 | `webhook-delivery` | NN-10 | B38 B56 B58 | — |
| PAY-REQ-0007 | 事件目录与版本化 | CAP-02 | `domain-events` | NN-04 | B12 B91 | 0006 |
| PAY-REQ-0008 | 路由规则版本化 | CAP-03 | `merchant-config` | NN-11 CTRL-016 | B28 B30 | — |
| PAY-REQ-0009 | 渠道能力矩阵 | CAP-03 | `merchant-config` | CTRL-016 | B27 B62 | — |
| PAY-REQ-0010 | 支付尝试可追溯 | CAP-04 | `payment-core` | CTRL-007 | B33 | 0001 |
| PAY-REQ-0011 | 不确定状态主动查询 | CAP-04 | `payment-core` | NN-03 | B33 B100 | 0004 |
| PAY-REQ-0012 | 状态机单向转换 | CAP-04 | `payment-core` | NN-04 | B10 | — |
| PAY-REQ-0013 | 外部调用弹性 | CAP-04 | `payment-core` | CTRL-017 | B100 B117 | — |
| PAY-REQ-0014 | 微信支付 APIv3 全模式 | CAP-05 | `wechat-pay` | CTRL-002 | B40 B41 B42 B43 | — |
| PAY-REQ-0015 | 支付宝证书模式全模式 | CAP-05 | `alipay` | CTRL-002 | B44 B45 B46 B47 | — |
| PAY-REQ-0016 | Stripe 托管字段 | CAP-05 | `stripe` | NN-02 CTRL-001 | B48 B49 | 0007 |
| PAY-REQ-0017 | PayPal Orders v2 | CAP-05 | `paypal` | CTRL-002 | B51 B52 | — |
| PAY-REQ-0018 | Apple Pay 经 PSP | CAP-05 | `apple-pay` | NN-02 CTRL-001 | B53 B54 | 0007 |
| PAY-REQ-0019 | 回调先验签 | CAP-06 | `webhook-ingress` | NN-08 CTRL-002 | B37 B114 | 0004 |
| PAY-REQ-0020 | Inbox 去重 | CAP-06 | `webhook-ingress` | NN-04 CTRL-003 | B12 B37 B115 | 0005 |
| PAY-REQ-0021 | 原始回调留存 | CAP-06 | `webhook-ingress` | NN-11 CTRL-007 | B37 B101 | — |
| PAY-REQ-0022 | 退款不超可退余额 | CAP-07 | `payment-core` | NN-04 | B64 | — |
| PAY-REQ-0023 | 退款阈值审批 | CAP-07 | `payment-core` | NN-11 | B65 | — |
| PAY-REQ-0024 | 争议与拒付管理 | CAP-08 | `payment-core` | CTRL-009 | B66 | — |
| PAY-REQ-0025 | 订阅与周期计费 | CAP-08 | `payment-core` | CTRL-009 | B67 B70 B71 | — |
| PAY-REQ-0026 | Mandate 与令牌引用 | CAP-08 | `payment-core` | NN-02 | B68 | 0007 |
| PAY-REQ-0027 | 复式账本不可变 | CAP-09 | `ledger-service` | NN-06 CTRL-008 | B72 B73 | 0006 |
| PAY-REQ-0028 | 最小货币单位整数 | CAP-09 | `money` | NN-05 | B09 | 0003 |
| PAY-REQ-0029 | 费用汇率记录 | CAP-09 | `ledger-service` | CTRL-008 | B74 | — |
| PAY-REQ-0030 | 结算到账视图 | CAP-09 | `ledger-service` | NN-13 | B75 | — |
| PAY-REQ-0031 | 财务修正反向分录 | CAP-09 | `ledger-service` | NN-06 NN-11 | B73 B78 | — |
| PAY-REQ-0032 | 账单文件幂等摄取 | CAP-10 | `reconciliation-service` | NN-04 CTRL-009 | B76 | — |
| PAY-REQ-0033 | 三方对账 | CAP-10 | `reconciliation-service` | CTRL-009 | B77 B125 | — |
| PAY-REQ-0034 | 差错处置复核 | CAP-10 | `reconciliation-service` | NN-11 CTRL-007 | B78 | — |
| PAY-REQ-0035 | 实时风控决策 | CAP-11 | `risk-engine` | CTRL-017 | B80 B82 | — |
| PAY-REQ-0036 | 风控信号采集 | CAP-11 | `risk-engine` | NN-14 CTRL-015 | B81 | — |
| PAY-REQ-0037 | 名单与案件 | CAP-11 | `risk-engine` | CTRL-014 | B87 | — |
| PAY-REQ-0038 | 收银台页面完整性 | CAP-12 | `checkout-web` | CTRL-010 | B58 B59 B85 | — |
| PAY-REQ-0039 | 支付链接防篡改 | CAP-12 | `checkout-web` | NN-10 CTRL-010 | B57 B58 | — |
| PAY-REQ-0040 | 边缘鉴权与限流 | CAP-13 | `edge-gateway` | CTRL-014 CTRL-017 | B88 B89 | 0001 0009 0012 |
| PAY-REQ-0041 | 后台抗钓鱼认证 | CAP-14 | `admin-web` | NN-11 CTRL-004 | B18 B19 | 0009 |
| PAY-REQ-0042 | 最小权限与职责分离 | CAP-14 | `admin-web` | CTRL-014 | B19 B17 | 0009 |
| PAY-REQ-0043 | 不可抵赖审计 | CAP-15 | `audit` | CTRL-007 | B23 | — |
| PAY-REQ-0044 | 密钥生命周期 | CAP-15 | `security` | NN-07 CTRL-006 | B20 B21 | 0008 |
| PAY-REQ-0045 | 租户隔离全链路 | CAP-15 | `merchant-config` | NN-09 CTRL-005 | B31 | — |
| PAY-REQ-0046 | 可观测性与脱敏 | CAP-16 | `observability` | NN-14 CTRL-015 | B96 B108 | — |
| PAY-REQ-0047 | SLO 与错误预算 | CAP-16 | `observability` | CTRL-012 | B97 | — |
| PAY-REQ-0048 | 备份恢复与演练 | CAP-16 | `worker-scheduler` | CTRL-013 | B90 B95 | — |
| PAY-REQ-0049 | 证据与独立评审 | CAP-17 | `payment-core` | NN-12 CTRL-020 | B06 B119 B127 | 0010 0011 0012 0013 |
| PAY-REQ-0050 | 受监管能力边界 | CAP-17 | `merchant-config` | NN-13 | B107 | — |
| PAY-REQ-0051 | 安全例外与剩余风险台账 | CAP-17 | `security` | NN-15 | B02 B110 | — |
| PAY-REQ-0052 | 第三方与供应商风险 | CAP-17 | `merchant-config` | CTRL-019 | B111 | — |
| PAY-REQ-0053 | 安全 SDLC 与不可变发布 | CAP-18 | `edge-gateway` | CTRL-011 CTRL-018 | B05 B109 B124 | — |

## 控制 → 需求（反向覆盖）

| 控制 | 被哪些需求认领 |
| --- | --- |
| NN-01 | PAY-REQ-0001 |
| NN-02 | PAY-REQ-0016 PAY-REQ-0018 PAY-REQ-0026 |
| NN-03 | PAY-REQ-0005 PAY-REQ-0011 |
| NN-04 | PAY-REQ-0002 PAY-REQ-0003 PAY-REQ-0007 PAY-REQ-0012 PAY-REQ-0020 PAY-REQ-0022 PAY-REQ-0032 |
| NN-05 | PAY-REQ-0028 |
| NN-06 | PAY-REQ-0027 PAY-REQ-0031 |
| NN-07 | PAY-REQ-0044 |
| NN-08 | PAY-REQ-0019 |
| NN-09 | PAY-REQ-0004 PAY-REQ-0045 |
| NN-10 | PAY-REQ-0006 PAY-REQ-0039 |
| NN-11 | PAY-REQ-0008 PAY-REQ-0021 PAY-REQ-0023 PAY-REQ-0031 PAY-REQ-0034 PAY-REQ-0041 |
| NN-12 | PAY-REQ-0049 |
| NN-13 | PAY-REQ-0030 PAY-REQ-0050 |
| NN-14 | PAY-REQ-0036 PAY-REQ-0046 |
| NN-15 | PAY-REQ-0051 |
| CTRL-001 | PAY-REQ-0016 PAY-REQ-0018 |
| CTRL-002 | PAY-REQ-0005 PAY-REQ-0014 PAY-REQ-0015 PAY-REQ-0017 PAY-REQ-0019 |
| CTRL-003 | PAY-REQ-0002 PAY-REQ-0003 PAY-REQ-0020 |
| CTRL-004 | PAY-REQ-0041 |
| CTRL-005 | PAY-REQ-0045 |
| CTRL-006 | PAY-REQ-0044 |
| CTRL-007 | PAY-REQ-0010 PAY-REQ-0021 PAY-REQ-0034 PAY-REQ-0043 |
| CTRL-008 | PAY-REQ-0027 PAY-REQ-0029 |
| CTRL-009 | PAY-REQ-0024 PAY-REQ-0025 PAY-REQ-0032 PAY-REQ-0033 |
| CTRL-010 | PAY-REQ-0038 PAY-REQ-0039 |
| CTRL-011 | PAY-REQ-0053 |
| CTRL-012 | PAY-REQ-0047 |
| CTRL-013 | PAY-REQ-0048 |
| CTRL-014 | PAY-REQ-0037 PAY-REQ-0040 PAY-REQ-0042 |
| CTRL-015 | PAY-REQ-0036 PAY-REQ-0046 |
| CTRL-016 | PAY-REQ-0004 PAY-REQ-0008 PAY-REQ-0009 |
| CTRL-017 | PAY-REQ-0013 PAY-REQ-0035 PAY-REQ-0040 |
| CTRL-018 | PAY-REQ-0053 |
| CTRL-019 | PAY-REQ-0052 |
| CTRL-020 | PAY-REQ-0049 |
