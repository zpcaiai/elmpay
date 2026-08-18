<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/requirements.json
     Regenerate with: python3 scripts/render-docs.py -->

# 需求基线（B01）

共 50 条需求，17 个类别。
每条需求都绑定至少一个控制与至少一个验证批次；未绑定的需求会使治理门禁失败。

## admin

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0041 | 后台抗钓鱼认证 | MUST | admin-web | NN-11 CTRL-004 | B18 B19 |
| PAY-REQ-0042 | 最小权限与职责分离 | MUST | admin-web | CTRL-014 | B19 B17 |

## checkout

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0038 | 收银台页面完整性 | MUST | checkout-web | CTRL-010 | B58 B59 B85 |
| PAY-REQ-0039 | 支付链接防篡改 | MUST | checkout-web | NN-10 CTRL-010 | B57 B58 |

## dispute

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0024 | 争议与拒付管理 | MUST | payment-core | CTRL-009 | B66 |

## governance

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0049 | 证据与独立评审 | MUST | payment-core | NN-12 CTRL-020 | B06 B119 B127 |
| PAY-REQ-0050 | 受监管能力边界 | MUST | merchant-config | NN-13 | B107 |

## integration

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0005 | 支付事实签名投递 | MUST | webhook-delivery | NN-03 CTRL-002 | B38 B114 |
| PAY-REQ-0006 | 回调地址白名单 | MUST | webhook-delivery | NN-10 | B38 B56 B58 |
| PAY-REQ-0007 | 事件目录与版本化 | MUST | domain-events | NN-04 | B12 B91 |

## ledger

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0027 | 复式账本不可变 | MUST | ledger-service | NN-06 CTRL-008 | B72 B73 |
| PAY-REQ-0028 | 最小货币单位整数 | MUST | money | NN-05 | B09 |
| PAY-REQ-0029 | 费用汇率记录 | MUST | ledger-service | CTRL-008 | B74 |
| PAY-REQ-0030 | 结算到账视图 | MUST | ledger-service | NN-13 | B75 |
| PAY-REQ-0031 | 财务修正反向分录 | MUST | ledger-service | NN-06 NN-11 | B73 B78 |

## operations

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0046 | 可观测性与脱敏 | MUST | observability | NN-14 CTRL-015 | B96 B108 |
| PAY-REQ-0047 | SLO 与错误预算 | MUST | observability | CTRL-012 | B97 |
| PAY-REQ-0048 | 备份恢复与演练 | MUST | worker-scheduler | CTRL-013 | B90 B95 |

## orchestration

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0008 | 路由规则版本化 | MUST | merchant-config | NN-11 CTRL-016 | B28 B30 |
| PAY-REQ-0009 | 渠道能力矩阵 | MUST | merchant-config | CTRL-016 | B27 B62 |
| PAY-REQ-0010 | 支付尝试可追溯 | MUST | payment-core | CTRL-007 | B33 |
| PAY-REQ-0011 | 不确定状态主动查询 | MUST | payment-core | NN-03 | B33 B100 |
| PAY-REQ-0012 | 状态机单向转换 | MUST | payment-core | NN-04 | B10 |
| PAY-REQ-0013 | 外部调用弹性 | MUST | payment-core | CTRL-017 | B100 B117 |

## order-intake

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0001 | 多项目 Payment Intent 接入 | MUST | payment-core | NN-01 | B15 B32 B120 |
| PAY-REQ-0002 | 外部引用唯一绑定 | MUST | payment-core | NN-04 CTRL-003 | B32 B36 |
| PAY-REQ-0003 | 创建幂等键必填 | MUST | idempotency | NN-04 CTRL-003 | B36 B115 |
| PAY-REQ-0004 | 项目注册与凭证签发 | MUST | merchant-config | NN-09 CTRL-016 | B24 B30 |

## platform

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0040 | 边缘鉴权与限流 | MUST | edge-gateway | CTRL-014 CTRL-017 | B88 B89 |

## provider

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0014 | 微信支付 APIv3 全模式 | MUST | wechat-pay | CTRL-002 | B40 B41 B42 B43 |
| PAY-REQ-0015 | 支付宝证书模式全模式 | MUST | alipay | CTRL-002 | B44 B45 B46 B47 |
| PAY-REQ-0016 | Stripe 托管字段 | MUST | stripe | NN-02 CTRL-001 | B48 B49 |
| PAY-REQ-0017 | PayPal Orders v2 | MUST | paypal | CTRL-002 | B51 B52 |
| PAY-REQ-0018 | Apple Pay 经 PSP | MUST | apple-pay | NN-02 CTRL-001 | B53 B54 |

## reconciliation

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0032 | 账单文件幂等摄取 | MUST | reconciliation-service | NN-04 CTRL-009 | B76 |
| PAY-REQ-0033 | 三方对账 | MUST | reconciliation-service | CTRL-009 | B77 B125 |
| PAY-REQ-0034 | 差错处置复核 | MUST | reconciliation-service | NN-11 CTRL-007 | B78 |

## refund

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0022 | 退款不超可退余额 | MUST | payment-core | NN-04 | B64 |
| PAY-REQ-0023 | 退款阈值审批 | MUST | payment-core | NN-11 | B65 |

## risk

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0035 | 实时风控决策 | MUST | risk-engine | CTRL-017 | B80 B82 |
| PAY-REQ-0036 | 风控信号采集 | MUST | risk-engine | NN-14 CTRL-015 | B81 |
| PAY-REQ-0037 | 名单与案件 | SHOULD | risk-engine | CTRL-014 | B87 |

## security

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0043 | 不可抵赖审计 | MUST | audit | CTRL-007 | B23 |
| PAY-REQ-0044 | 密钥生命周期 | MUST | security | NN-07 CTRL-006 | B20 B21 |
| PAY-REQ-0045 | 租户隔离全链路 | MUST | merchant-config | NN-09 CTRL-005 | B31 |

## subscription

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0025 | 订阅与周期计费 | SHOULD | payment-core | CTRL-009 | B67 B70 B71 |
| PAY-REQ-0026 | Mandate 与令牌引用 | MUST | payment-core | NN-02 | B68 |

## webhook

| ID | 标题 | 优先级 | 责任模块 | 控制 | 验证批次 |
| --- | --- | --- | --- | --- | --- |
| PAY-REQ-0019 | 回调先验签 | MUST | webhook-ingress | NN-08 CTRL-002 | B37 B114 |
| PAY-REQ-0020 | Inbox 去重 | MUST | webhook-ingress | NN-04 CTRL-003 | B12 B37 B115 |
| PAY-REQ-0021 | 原始回调留存 | MUST | webhook-ingress | NN-11 CTRL-007 | B37 B101 |

## 需求详情

### PAY-REQ-0001 多项目 Payment Intent 接入

- 类别：order-intake　优先级：MUST　责任模块：`payment-core`
- 陈述：业务项目通过 Payment Intent API 发起支付，平台不接收商品、库存与履约明细。
- 验收：以业务订单明细字段提交的请求被拒绝，且拒绝原因可机读。
- 控制：NN-01
- 验证批次：B15（现有项目订单迁移架构）, B32（Payment Intent 服务）, B120（现有项目接入适配器）

### PAY-REQ-0002 外部引用唯一绑定

- 类别：order-intake　优先级：MUST　责任模块：`payment-core`
- 陈述：每个 Payment Intent 以 (project_id, business_order_no) 唯一绑定业务订单，重复绑定被数据库唯一约束拒绝。
- 验收：并发重复创建只产生一条 Intent，其余返回同一资源。
- 控制：NN-04, CTRL-003
- 验证批次：B32（Payment Intent 服务）, B36（幂等、去重与并发控制）

### PAY-REQ-0003 创建幂等键必填

- 类别：order-intake　优先级：MUST　责任模块：`idempotency`
- 陈述：创建、确认、捕获、退款请求必须携带幂等键；相同键与相同载荷返回首次结果，载荷不同返回冲突。
- 验收：64 并发写者下无重复副作用；载荷哈希不一致返回 409。
- 控制：NN-04, CTRL-003
- 验证批次：B36（幂等、去重与并发控制）, B115（并发、重复、乱序与时钟测试）

### PAY-REQ-0004 项目注册与凭证签发

- 类别：order-intake　优先级：MUST　责任模块：`merchant-config`
- 陈述：业务项目必须先在平台注册并获得独立密钥与回调配置，未注册项目的请求一律拒绝。
- 验收：跨项目使用他人密钥的请求被拒绝并记录审计。
- 控制：NN-09, CTRL-016
- 验证批次：B24（租户与项目注册中心）, B30（商户接入与四眼审批）

### PAY-REQ-0005 支付事实签名投递

- 类别：integration　优先级：MUST　责任模块：`webhook-delivery`
- 陈述：平台通过签名 Webhook 把支付事实投递回业务项目，至少一次投递，消费侧幂等。
- 验收：重复投递不产生重复履约；签名错误的投递被消费方拒绝。
- 控制：NN-03, CTRL-002
- 验证批次：B38（业务项目 Webhook 与事件投递）, B114（Webhook 回放、模糊与故障注入）

### PAY-REQ-0006 回调地址白名单

- 类别：integration　优先级：MUST　责任模块：`webhook-delivery`
- 陈述：业务项目回调地址、return_url、支付链接域名只接受登记域名或不可变内部路径。
- 验收：任意外部域名与内网地址（SSRF 载荷）均被拒绝。
- 控制：NN-10
- 验证批次：B38（业务项目 Webhook 与事件投递）, B56（托管收银台服务）, B58（防篡改 Checkout Session）

### PAY-REQ-0007 事件目录与版本化

- 类别：integration　优先级：MUST　责任模块：`domain-events`
- 陈述：所有领域事件登记在事件目录中，采用相加式演进；破坏性变更必须新版本主题。
- 验收：删除或改变既有字段语义的事件 schema 变更在 CI 中被阻断。
- 控制：NN-04
- 验证批次：B12（事件目录、Outbox 与 Inbox）, B91（Kafka 事件耐久性与业务幂等）

### PAY-REQ-0008 路由规则版本化

- 类别：orchestration　优先级：MUST　责任模块：`merchant-config`
- 陈述：渠道路由与灰度规则受版本控制，变更需四眼复核并可即时回滚。
- 验收：未复核的路由变更无法生效；回滚可在一次操作内完成。
- 控制：NN-11, CTRL-016
- 验证批次：B28（路由规则、灰度与配置版本）, B30（商户接入与四眼审批）

### PAY-REQ-0009 渠道能力矩阵

- 类别：orchestration　优先级：MUST　责任模块：`merchant-config`
- 陈述：可用支付方式由渠道能力与地区政策矩阵计算，而不是硬编码在客户端。
- 验收：关闭某渠道能力后收银台立即不再展示该方式。
- 控制：CTRL-016
- 验证批次：B27（渠道能力与地区政策矩阵）, B62（能力检测、降级与回退）

### PAY-REQ-0010 支付尝试可追溯

- 类别：orchestration　优先级：MUST　责任模块：`payment-core`
- 陈述：每次渠道交互产生一条 Payment Attempt，含请求摘要、响应、耗时、错误分类与追踪 ID。
- 验收：任一支付可完整重建其渠道交互时间线。
- 控制：CTRL-007
- 验证批次：B33（支付尝试与渠道交易）

### PAY-REQ-0011 不确定状态主动查询

- 类别：orchestration　优先级：MUST　责任模块：`payment-core`
- 陈述：渠道超时或返回不确定结果时，必须通过主动查询或对账确认最终状态，不得默认失败或成功。
- 验收：注入超时故障后状态最终收敛且无重复扣款。
- 控制：NN-03
- 验证批次：B33（支付尝试与渠道交易）, B100（渠道健康、熔断与故障转移）

### PAY-REQ-0012 状态机单向转换

- 类别：orchestration　优先级：MUST　责任模块：`payment-core`
- 陈述：支付、退款、订阅、争议状态机只允许声明的单向或补偿式转换，非法转换被拒绝并告警。
- 验收：属性测试穷举非法转换全部被拒绝。
- 控制：NN-04
- 验证批次：B10（支付状态机与业务不变量）

### PAY-REQ-0013 外部调用弹性

- 类别：orchestration　优先级：MUST　责任模块：`payment-core`
- 陈述：所有渠道调用设置超时、有限重试、熔断与降级，且重试不放大副作用。
- 验收：渠道故障注入下核心接口不超过 SLO 且不产生重复请求副作用。
- 控制：CTRL-017
- 验证批次：B100（渠道健康、熔断与故障转移）, B117（性能、负载、耐久与容量测试）

### PAY-REQ-0014 微信支付 APIv3 全模式

- 类别：provider　优先级：MUST　责任模块：`wechat-pay`
- 陈述：支持 JSAPI、小程序、Native、H5 与 App 支付，含退款、关单、查询与账单。
- 验收：官方沙箱全模式契约测试通过。
- 控制：CTRL-002
- 验证批次：B40（微信支付 APIv3 核心与凭证）, B41（微信 JSAPI 与小程序支付）, B42（微信 Native、H5 与 App 支付）, B43（微信退款、关单、查询与账单）

### PAY-REQ-0015 支付宝证书模式全模式

- 类别：provider　优先级：MUST　责任模块：`alipay`
- 陈述：以证书模式支持电脑网站、手机网站、App、当面付与小程序支付及退款、关闭、查询、账单。
- 验收：证书轮换后交易与验签仍然成功。
- 控制：CTRL-002
- 验证批次：B44（支付宝证书模式与核心 SDK）, B45（支付宝电脑、手机网站与 App 支付）, B46（支付宝当面付与小程序支付）, B47（支付宝退款、关闭、查询、账单与通知）

### PAY-REQ-0016 Stripe 托管字段

- 类别：provider　优先级：MUST　责任模块：`stripe`
- 陈述：Stripe 卡支付只经 Elements/PaymentSheet 与令牌化，服务端不接触 PAN/CVV。
- 验收：服务端请求体扫描无卡号字段；PCI 范围证据留存。
- 控制：NN-02, CTRL-001
- 验证批次：B48（Stripe PaymentIntents 与令牌化卡支付）, B49（Stripe Webhook、退款与争议）

### PAY-REQ-0017 PayPal Orders v2

- 类别：provider　优先级：MUST　责任模块：`paypal`
- 陈述：支持 PayPal 授权、捕获、退款、争议与订阅，Webhook 证书链校验。
- 验收：沙箱授权-捕获-退款闭环与验签负向用例通过。
- 控制：CTRL-002
- 验证批次：B51（PayPal Orders v2 授权与捕获）, B52（PayPal Webhook、退款、争议与订阅）

### PAY-REQ-0018 Apple Pay 经 PSP

- 类别：provider　优先级：MUST　责任模块：`apple-pay`
- 陈述：Apple Pay token 直接转交 PSP，平台不解密，域名验证文件受完整性监控。
- 验收：平台无解密密钥；域名验证文件变更触发告警。
- 控制：NN-02, CTRL-001
- 验证批次：B53（Apple Pay Web 与 iOS）, B54（Apple Pay 域名、证书与商户令牌）

### PAY-REQ-0019 回调先验签

- 类别：webhook　优先级：MUST　责任模块：`webhook-ingress`
- 陈述：渠道回调必须先验证签名、时间戳、nonce、序列号与商户/订单/金额绑定，再持久化与处理。
- 验收：伪造与重放夹具全部被拒绝且不产生业务效果。
- 控制：NN-08, CTRL-002
- 验证批次：B37（渠道 Webhook 入口）, B114（Webhook 回放、模糊与故障注入）

### PAY-REQ-0020 Inbox 去重

- 类别：webhook　优先级：MUST　责任模块：`webhook-ingress`
- 陈述：回调进入持久 Inbox，按渠道事件 ID 去重，容忍乱序与重复。
- 验收：乱序与重复回放后最终状态一致且只有一次业务效果。
- 控制：NN-04, CTRL-003
- 验证批次：B12（事件目录、Outbox 与 Inbox）, B37（渠道 Webhook 入口）, B115（并发、重复、乱序与时钟测试）

### PAY-REQ-0021 原始回调留存

- 类别：webhook　优先级：MUST　责任模块：`webhook-ingress`
- 陈述：回调原始报文按保留策略留存并可回放，回放为高风险操作需四眼复核。
- 验收：回放操作留下主体、理由与工单的审计记录。
- 控制：NN-11, CTRL-007
- 验证批次：B37（渠道 Webhook 入口）, B101（运营控制台与安全回放）

### PAY-REQ-0022 退款不超可退余额

- 类别：refund　优先级：MUST　责任模块：`payment-core`
- 陈述：退款金额不得超过该支付的可退余额，含手续费与部分退款场景。
- 验收：属性测试下不存在任何可超额退款的路径。
- 控制：NN-04
- 验证批次：B64（退款编排）

### PAY-REQ-0023 退款阈值审批

- 类别：refund　优先级：MUST　责任模块：`payment-core`
- 陈述：超过阈值或高风险的退款必须四眼审批后执行。
- 验收：未审批的高额退款请求被拒绝并进入待审队列。
- 控制：NN-11
- 验证批次：B65（退款风险与审批）

### PAY-REQ-0024 争议与拒付管理

- 类别：dispute　优先级：MUST　责任模块：`payment-core`
- 陈述：争议、拒付的证据提交、时限与结果同步到账本与业务项目。
- 验收：争议状态变化产生对应账本分录与业务通知。
- 控制：CTRL-009
- 验证批次：B66（争议与拒付管理）

### PAY-REQ-0025 订阅与周期计费

- 类别：subscription　优先级：SHOULD　责任模块：`payment-core`
- 陈述：支持订阅创建、变更、取消、比例计费与余额抵扣，计费结果可对账。
- 验收：订阅生命周期端到端认证用例通过。
- 控制：CTRL-009
- 验证批次：B67（订阅与周期计费领域）, B70（取消、比例计费、余额抵扣与贷项）, B71（退款争议订阅端到端认证）

### PAY-REQ-0026 Mandate 与令牌引用

- 类别：subscription　优先级：MUST　责任模块：`payment-core`
- 陈述：周期扣款依据 Mandate 与 PSP 令牌引用，平台不存储可复用明文令牌。
- 验收：数据库扫描无可复用明文支付令牌。
- 控制：NN-02
- 验证批次：B68（Mandate 与支付令牌引用）

### PAY-REQ-0027 复式账本不可变

- 类别：ledger　优先级：MUST　责任模块：`ledger-service`
- 陈述：所有资金事实以复式分录记录，分录禁止 UPDATE/DELETE，借贷必平。
- 验收：数据库层拒绝对分录的更新与删除；余额恒等式属性测试通过。
- 控制：NN-06, CTRL-008
- 验证批次：B72（不可变复式账本）, B73（过账规则与账本不变量）

### PAY-REQ-0028 最小货币单位整数

- 类别：ledger　优先级：MUST　责任模块：`money`
- 陈述：所有金额以最小货币单位整数表示，币种小数位来自受版本控制的货币元数据。
- 验收：代码扫描无浮点金额；零小数币种用例正确。
- 控制：NN-05
- 验证批次：B09（金额、币种与精度模型）

### PAY-REQ-0029 费用汇率记录

- 类别：ledger　优先级：MUST　责任模块：`ledger-service`
- 陈述：手续费、税费、汇率与舍入过程逐笔记录，可重算。
- 验收：任一笔结算金额可由记录的输入重算得到相同结果。
- 控制：CTRL-008
- 验证批次：B74（手续费、税费、舍入与汇率）

### PAY-REQ-0030 结算到账视图

- 类别：ledger　优先级：MUST　责任模块：`ledger-service`
- 陈述：提供结算指令与到账视图，结算由持牌机构直达商户，不经平台资金池。
- 验收：配置中不存在平台自有资金池账户类型。
- 控制：NN-13
- 验证批次：B75（结算指令与到账视图）

### PAY-REQ-0031 财务修正反向分录

- 类别：ledger　优先级：MUST　责任模块：`ledger-service`
- 陈述：财务修正只能通过反向或调整分录完成，并记录理由与复核人。
- 验收：直接修改历史分录的尝试在数据库与应用层均失败。
- 控制：NN-06, NN-11
- 验证批次：B73（过账规则与账本不变量）, B78（差错、人工调整与复核）

### PAY-REQ-0032 账单文件幂等摄取

- 类别：reconciliation　优先级：MUST　责任模块：`reconciliation-service`
- 陈述：渠道账单与银行文件按文件摘要幂等摄取，重复摄取不产生重复记录。
- 验收：同一文件重复导入后记录数不变。
- 控制：NN-04, CTRL-009
- 验证批次：B76（渠道账单与银行文件摄取）

### PAY-REQ-0033 三方对账

- 类别：reconciliation　优先级：MUST　责任模块：`reconciliation-service`
- 陈述：业务订单、平台支付、渠道账单与银行到账逐笔匹配，差异分类可解释。
- 验收：日终对账产出差异清单且每条差异有分类与处置。
- 控制：CTRL-009
- 验证批次：B77（三方对账引擎）, B125（上线后监控与日终对账）

### PAY-REQ-0034 差错处置复核

- 类别：reconciliation　优先级：MUST　责任模块：`reconciliation-service`
- 陈述：人工调整与差错处置必须四眼复核并写入不可变审计。
- 验收：单人无法完成任何人工资金调整。
- 控制：NN-11, CTRL-007
- 验证批次：B78（差错、人工调整与复核）

### PAY-REQ-0035 实时风控决策

- 类别：risk　优先级：MUST　责任模块：`risk-engine`
- 陈述：支付创建与确认前经过实时风控决策，决策结果可解释并可回溯到规则版本。
- 验收：任一拒绝决策可还原触发规则与输入特征摘要。
- 控制：CTRL-017
- 验证批次：B80（实时支付风控引擎）, B82（规则引擎、版本与解释）

### PAY-REQ-0036 风控信号采集

- 类别：risk　优先级：MUST　责任模块：`risk-engine`
- 陈述：采集速度、设备、网络与账户信号，特征不包含不必要个人信息。
- 验收：特征存储扫描无身份证件、完整卡号与完整地址。
- 控制：NN-14, CTRL-015
- 验证批次：B81（速度、设备、网络与账户信号）

### PAY-REQ-0037 名单与案件

- 类别：risk　优先级：SHOULD　责任模块：`risk-engine`
- 陈述：支持名单管理与案件处置，名单变更受权限与审计约束。
- 验收：名单变更留下主体、理由与前后值。
- 控制：CTRL-014
- 验证批次：B87（风险运营、案件与名单管理）

### PAY-REQ-0038 收银台页面完整性

- 类别：checkout　优先级：MUST　责任模块：`checkout-web`
- 陈述：托管收银台强制 CSP、SRI、Trusted Types 与脚本清单，变更触发完整性告警。
- 验收：注入外部脚本的尝试被 CSP 阻断并产生告警。
- 控制：CTRL-010
- 验证批次：B58（防篡改 Checkout Session）, B59（Web 收银台 UI）, B85（E-skimming、脚本供应链与浏览器完整性）

### PAY-REQ-0039 支付链接防篡改

- 类别：checkout　优先级：MUST　责任模块：`checkout-web`
- 陈述：支付链接与二维码经签名，金额、商户与过期时间不可篡改。
- 验收：篡改链接参数导致签名校验失败。
- 控制：NN-10, CTRL-010
- 验证批次：B57（支付链接与二维码服务）, B58（防篡改 Checkout Session）

### PAY-REQ-0040 边缘鉴权与限流

- 类别：platform　优先级：MUST　责任模块：`edge-gateway`
- 陈述：公共入口统一鉴权、请求规范化、限流与 WAF 上下文，内部调用强制 mTLS。
- 验收：绕过网关直连内部服务的尝试被网络策略拒绝。
- 控制：CTRL-014, CTRL-017
- 验证批次：B88（API Gateway、WAF 与限流）, B89（服务网格、mTLS 与网络策略）

### PAY-REQ-0041 后台抗钓鱼认证

- 类别：admin　优先级：MUST　责任模块：`admin-web`
- 陈述：管理后台强制 WebAuthn/硬件密钥，高风险操作需要 step-up。
- 验收：仅密码或短信 OTP 无法登录后台。
- 控制：NN-11, CTRL-004
- 验证批次：B18（抗钓鱼 MFA 与 WebAuthn）, B19（RBAC、ABAC、职责分离与临时授权）

### PAY-REQ-0042 最小权限与职责分离

- 类别：admin　优先级：MUST　责任模块：`admin-web`
- 陈述：后台与服务身份采用 RBAC/ABAC、职责分离与临时授权，定期访问复核。
- 验收：同一主体无法同时具备发起与审批权限。
- 控制：CTRL-014
- 验证批次：B19（RBAC、ABAC、职责分离与临时授权）, B17（客户、管理员与服务身份）

### PAY-REQ-0043 不可抵赖审计

- 类别：security　优先级：MUST　责任模块：`audit`
- 陈述：所有资金与权限操作写入防篡改审计，含主体、理由、工单、前后值与追踪。
- 验收：审计篡改可被完整性校验检出。
- 控制：CTRL-007
- 验证批次：B23（不可抵赖审计与防篡改日志）

### PAY-REQ-0044 密钥生命周期

- 类别：security　优先级：MUST　责任模块：`security`
- 陈述：私钥与 API 密钥由 KMS/HSM/Vault 管理，轮换具备重叠窗口、审计与演练。
- 验收：密钥轮换演练在不中断交易的前提下完成。
- 控制：NN-07, CTRL-006
- 验证批次：B20（KMS、HSM 与信封加密）, B21（密钥、证书与域名生命周期）

### PAY-REQ-0045 租户隔离全链路

- 类别：security　优先级：MUST　责任模块：`merchant-config`
- 陈述：API、数据库、缓存、消息、对象存储、日志与导出均校验租户上下文。
- 验收：跨租户读取与导出攻击用例全部失败。
- 控制：NN-09, CTRL-005
- 验证批次：B31（租户隔离验证）

### PAY-REQ-0046 可观测性与脱敏

- 类别：operations　优先级：MUST　责任模块：`observability`
- 陈述：日志、指标与追踪遵循 OpenTelemetry，且默认拒绝记录凭证、卡数据与不必要个人信息。
- 验收：日志脱敏过滤器针对凭证语料测试通过。
- 控制：NN-14, CTRL-015
- 验证批次：B96（OpenTelemetry 日志指标追踪）, B108（数据分类、保留、删除与令牌化）

### PAY-REQ-0047 SLO 与错误预算

- 类别：operations　优先级：MUST　责任模块：`observability`
- 陈述：核心支付、回调与查询各自定义 SLI/SLO、错误预算与告警。
- 验收：错误预算耗尽触发发布冻结流程。
- 控制：CTRL-012
- 验证批次：B97（SLI、SLO、错误预算与告警）

### PAY-REQ-0048 备份恢复与演练

- 类别：operations　优先级：MUST　责任模块：`worker-scheduler`
- 陈述：PostgreSQL PITR、跨区域备份与恢复演练满足 RPO≤5min、RTO≤30min。
- 验收：恢复演练产出可验证的恢复时间与数据完整性证据。
- 控制：CTRL-013
- 验证批次：B90（PostgreSQL 高可用、备份与 PITR）, B95（业务连续性、混沌与恢复演练）

### PAY-REQ-0049 证据与独立评审

- 类别：governance　优先级：MUST　责任模块：`payment-core`
- 陈述：每个批次的完成必须有自动化测试、运行证据、追踪关系与非唯一实现者的独立评审。
- 验收：缺任一证据时编排器 validate 失败并阻断发布。
- 控制：NN-12, CTRL-020
- 验证批次：B06（批次编排与证据框架）, B119（合规证据与独立评审门）, B127（最终生产认证与发布签署）

### PAY-REQ-0050 受监管能力边界

- 类别：governance　优先级：MUST　责任模块：`merchant-config`
- 陈述：不提供储值、资金池、跨商户清分与无牌代收代付；边界变更需牌照与合规批次。
- 验收：配置中开启任一受监管能力会使治理门禁失败。
- 控制：NN-13
- 验证批次：B107（AML、KYC、KYB、制裁与监管边界）
