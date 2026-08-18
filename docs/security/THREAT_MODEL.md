<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/threat-model.json
     Regenerate with: python3 scripts/render-docs.py -->

# 威胁模型与剩余风险台账（B02）

## 信任域

| ID | 名称 | 信任级别 |
| --- | --- | --- |
| Z01 | 用户浏览器/移动端 | untrusted |
| Z02 | 业务项目 | semi-trusted |
| Z03 | 公共边缘 | untrusted-ingress |
| Z04 | 支付核心 | trusted |
| Z05 | 连接器 | trusted-egress |
| Z06 | 支付渠道 | external |
| Z07 | 管理后台 | high-privilege |
| Z08 | 数据层 | trusted-data |
| Z09 | 消息层 | trusted-data |
| Z10 | KMS/HSM | crypto |
| Z11 | CI/CD | build |
| Z12 | 云控制面 | infrastructure |
| Z13 | 第三方监控与邮件短信 | external |

## 高价值资产

| ID | 资产 | 分类 | 责任人 | 模块 | 威胁 |
| --- | --- | --- | --- | --- | --- |
| AS-01 | 渠道私钥与 API 密钥 | secret | payment-platform-security | security | 泄露即可伪造交易与退款 |
| AS-02 | 商户号与渠道证书 | secret | payment-platform-connectors | merchant-config | 被替换后资金流向攻击者 |
| AS-03 | Payment Intent 与 Attempt | business-critical | payment-platform-architecture | payment-core | 被篡改可造成错误履约 |
| AS-04 | 支付与退款最终状态 | business-critical | payment-platform-architecture | payment-core | 伪造成功导致不可撤销履约 |
| AS-05 | 复式账本 | financial | payment-platform-finance | ledger-service | 被修改后资金差异不可解释 |
| AS-06 | 渠道账单与银行文件 | financial | payment-platform-finance | reconciliation-service | 被篡改可掩盖差错 |
| AS-07 | 管理员与财务身份 | identity | payment-platform-security | admin-web | 被攻陷可批量退款与导出 |
| AS-08 | 业务项目 Webhook 密钥 | secret | payment-platform-architecture | webhook-delivery | 泄露可伪造支付事实 |
| AS-09 | 个人信息 | personal-data | payment-platform-security | observability | 泄露触发隐私法律责任 |
| AS-10 | 发布制品与 CI 身份 | supply-chain | payment-platform-platform-eng | edge-gateway | 被替换可直达生产 |
| AS-11 | 治理单一事实源 | governance | payment-platform-architecture | merchant-config | 被篡改可静默移除红线 |

## 信任边界

| ID | 边界 | 跨越 | 控制 |
| --- | --- | --- | --- |
| TB-01 | 付款人到公共边缘 | Z01 ↔ Z03 | CTRL-010 CTRL-017 |
| TB-02 | 业务项目到公共边缘 | Z02 ↔ Z03 | CTRL-016 CTRL-014 |
| TB-03 | 公共边缘到支付核心 | Z03 ↔ Z04 | CTRL-014 CTRL-017 |
| TB-04 | 支付核心到连接器 | Z04 ↔ Z05 | CTRL-016 |
| TB-05 | 连接器到渠道 | Z05 ↔ Z06 | CTRL-002 CTRL-006 |
| TB-06 | 渠道回调到回调入口 | Z06 ↔ Z03 | CTRL-002 |
| TB-07 | 管理员到后台 | Z07 ↔ Z04 | CTRL-004 CTRL-014 |
| TB-08 | 服务到数据层 | Z04 ↔ Z08 | CTRL-005 CTRL-008 |
| TB-09 | 服务到消息层 | Z04 ↔ Z09 | CTRL-003 CTRL-005 |
| TB-10 | 服务到 KMS/HSM | Z04 ↔ Z10 | CTRL-006 |
| TB-11 | CI 到生产 | Z11 ↔ Z12 | CTRL-011 CTRL-018 |
| TB-12 | 服务到第三方监控与通知 | Z04 ↔ Z13 | CTRL-015 |

## 攻击者模型

| ID | 攻击者 | 能力 | 动机 |
| --- | --- | --- | --- |
| AD-01 | 外部欺诈者 | 低-中 | 盗刷、套现、拒付套利 |
| AD-02 | 钓鱼团伙 | 中 | 窃取后台与商户凭证 |
| AD-03 | 机器人与撞库者 | 中 | 批量试卡、账户接管 |
| AD-04 | 渠道凭证窃取者 | 中-高 | 伪造交易与退款 |
| AD-05 | 供应链攻击者 | 高 | 经依赖、镜像、CI 直达生产 |
| AD-06 | 恶意或被攻陷商户 | 中 | 伪造退款、洗钱、越权访问 |
| AD-07 | 内部人员 | 高 | 滥用权限修改资金与配置 |
| AD-08 | 被攻陷运维终端 | 高 | 以合法身份执行破坏操作 |
| AD-09 | DDoS 攻击者 | 中 | 造成支付不可用 |
| AD-10 | 财务欺诈者 | 中 | 操纵对账与差错掩盖损失 |

## 滥用案例

| ID | 滥用案例 | 攻击者 | 资产 | 控制 | 缓解批次 | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| AC-01 | 伪造或重放支付成功通知诱导履约 | AD-01 AD-04 | AS-04 AS-08 | NN-03 NN-08 CTRL-002 | B37 B38 B114 | planned |
| AC-02 | 篡改金额、币种、商户号、订单号、return_url 或渠道参数 | AD-01 AD-06 | AS-03 AS-04 | NN-08 NN-10 CTRL-002 | B37 B58 B114 | planned |
| AC-03 | 在创建/捕获/退款超时后重复调用造成双扣或双退 | AD-01 | AS-04 AS-05 | NN-04 CTRL-003 | B36 B115 | planned |
| AC-04 | 跨租户读取订单、重放 Webhook、盗用其他项目凭证 | AD-06 AD-07 | AS-03 AS-08 | NN-09 CTRL-005 CTRL-016 | B24 B31 B37 | planned |
| AC-05 | 攻陷后台后批量退款、改路由、导出数据或替换证书 | AD-02 AD-07 AD-08 | AS-02 AS-07 | NN-11 CTRL-004 CTRL-014 | B18 B19 B101 | planned |
| AC-06 | 注入第三方脚本窃取卡数据、会话或支付链接 | AD-05 AD-02 | AS-09 AS-04 | NN-02 CTRL-010 | B58 B59 B85 | planned |
| AC-07 | 注册同形域名、劫持 DNS、仿冒邮件或替换二维码 | AD-02 | AS-04 AS-09 | NN-10 CTRL-010 | B21 B84 | planned |
| AC-08 | 通过 SSRF 访问云元数据、KMS、内部管理端或白名单服务 | AD-05 AD-01 | AS-01 AS-10 | NN-10 CTRL-014 | B38 B88 B89 | planned |
| AC-09 | 通过注入修改支付状态或提取凭证 | AD-01 AD-06 | AS-03 AS-01 | NN-09 CTRL-011 | B22 B116 | planned |
| AC-10 | 破坏消息顺序、制造毒消息、阻断回调或操纵时钟 | AD-05 AD-09 | AS-04 AS-05 | NN-04 CTRL-003 | B91 B114 B115 | planned |
| AC-11 | 修改账本或对账差错掩盖退款、手续费、拒付与结算损失 | AD-07 AD-10 | AS-05 AS-06 | NN-06 NN-11 CTRL-008 CTRL-009 | B73 B78 B79 | planned |
| AC-12 | 通过依赖、CI token、镜像或 IaC 攻陷生产 | AD-05 | AS-10 AS-01 | CTRL-011 CTRL-018 | B05 B109 B110 | planned |

## 剩余风险台账

过期未复审的条目会使治理门禁失败（NN-15）。

| ID | 风险 | 严重度 | 风险所有者 | 补偿控制 | 到期日 | 复审批次 |
| --- | --- | --- | --- | --- | --- | --- |
| RR-01 | 生产渠道凭证尚未接入 KMS/HSM（当前仅 integration 环境） | medium | payment-platform-security | 仅存在 integration 环境且无生产凭证；治理门禁拒绝任何密钥字面量；凭证只能以 kms:// 或 vault:// 引用出现 | 2026-11-16 | B20 |
| RR-02 | Java 构建、SAST/DAST 与供应链扫描尚未接入（B03/B05 之前） | medium | payment-platform-platform-eng | 治理工具链零第三方依赖，供应链面积为零；仓库卫生扫描覆盖密钥与浮点金额；所有变更需 CODEOWNERS 复核 | 2026-10-17 | B05 |
| RR-03 | 反钓鱼、E-skimming 与页面完整性控制尚未实现 | medium | payment-platform-security | 尚无公开部署的收银台；支付链接与二维码域名策略已在需求基线中固化 | 2027-02-14 | B85 |
| RR-04 | 威胁模型尚未覆盖各渠道协议的具体攻击面 | low | payment-platform-connectors | 每个渠道批次强制更新威胁与控制；渠道适配统一契约限制爆炸半径 | 2026-12-16 | B55 |
| RR-05 | 证据由单一自动化执行者产生，独立审查依赖人工签署 | high | payment-platform-security | executor 与 reviewer 必须不同且由门禁强制；完成文件的每个字段可从仓库重新计算复核；15 项运行期负向控制证明门禁真会失败；所有产物摘要与提交 SHA 绑定 | 2026-09-17 | B119 |
| RR-06 | 版本目录中的具体 patch 版本与容器镜像摘要尚未对官方发布渠道核验（离线构建环境） | medium | payment-platform-platform-eng | 所有版本均为精确固定，禁止浮动版本与动态范围；容器镜像强制 digest 字段格式校验，占位摘要在 B04 联网构建代理上替换；生成式构建文件漂移检测，防止绕过目录直接改 build 脚本；每个条目均有所有者与升级策略，升级必须经 CODEOWNERS 复核 | 2026-12-16 | B109 |
