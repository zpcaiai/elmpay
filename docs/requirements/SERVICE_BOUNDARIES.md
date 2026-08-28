<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/service-boundaries.json
     Regenerate with: python3 scripts/render-docs.py -->

# 服务边界与禁止流（B01）

## 外部参与者与所有权

| 参与者 | 名称 | 拥有 | 禁止 |
| --- | --- | --- | --- |
| external:business-project | 业务项目 | 商品、库存、价格、促销、业务订单、履约、发票 | 直接访问支付平台数据库、以客户端回跳作为履约依据、持有其他项目的平台密钥 |
| external:end-customer | 付款人 | 支付授权行为 | 直接调用内部服务、决定支付最终状态 |
| external:payment-provider | 支付渠道 | 渠道交易最终状态、渠道账单 | 直接写入平台数据库、绕过验签影响平台状态 |
| external:acquirer-bank | 收单/银行 | 结算与到账 | 经由平台资金池结算 |
| external:admin-operator | 运营/财务/风控人员 | 经审批的运营决策 | 单人完成高风险资金或权限操作、绕过领域服务直接改支付状态 |
| external:kms-hsm | KMS/HSM/Vault | 密钥材料 | 把私钥导出到应用进程持久化存储 |
| external:monitoring | 监控与 SIEM | 遥测存储 | 接收未脱敏的凭证、卡数据或不必要个人信息 |

## 能力与责任模块

| 能力 | 名称 | 责任模块 | 需求数 | 入向 | 出向 |
| --- | --- | --- | --- | --- | --- |
| CAP-01 | 多项目支付接入 | payment-core | 4 | external:business-project | merchant-config、risk-engine |
| CAP-02 | 支付事实回传 | webhook-delivery | 3 | payment-core | external:business-project |
| CAP-03 | 路由与渠道能力 | merchant-config | 2 | payment-core、apps | payment-core |
| CAP-04 | 支付编排核心 | payment-core | 4 | edge-gateway、checkout-web | connectors、ledger-service、risk-engine |
| CAP-05 | 渠道适配 | payment-core | 5 | payment-core | external:payment-provider |
| CAP-06 | 渠道回调入口 | webhook-ingress | 3 | external:payment-provider | payment-core |
| CAP-07 | 退款编排与审批 | payment-core | 2 | admin-web、external:business-project | connectors、ledger-service |
| CAP-08 | 争议与订阅 | payment-core | 3 | webhook-ingress、worker-scheduler | ledger-service、webhook-delivery |
| CAP-09 | 账本与结算 | ledger-service | 5 | payment-core | reconciliation-service、admin-web |
| CAP-10 | 对账与差错 | reconciliation-service | 3 | worker-scheduler、external:acquirer-bank | ledger-service、admin-web |
| CAP-11 | 风险控制 | risk-engine | 3 | payment-core | payment-core、admin-web |
| CAP-12 | 托管收银台与支付链接 | checkout-web | 2 | external:end-customer | payment-core |
| CAP-13 | 边缘与网络安全 | edge-gateway | 1 | external:business-project、external:end-customer | payment-core、merchant-config |
| CAP-14 | 运营后台与权限 | admin-web | 2 | external:admin-operator | payment-core、risk-engine、ledger-service、reconciliation-service |
| CAP-15 | 安全基础设施 | security | 3 | all-modules | external:kms-hsm |
| CAP-16 | 可观测性与运维 | observability | 3 | all-modules | external:monitoring |
| CAP-17 | 治理与合规边界 | merchant-config | 4 | external:admin-operator | all-modules |
| CAP-18 | 安全供应链与不可变发布 | edge-gateway | 1 | all-modules | external:monitoring |
| CAP-19 | 移动客户端支付接入 | mobile-android | 1 | external:business-project、external:end-customer | edge-gateway |

### 能力到需求

- **CAP-01 多项目支付接入** → PAY-REQ-0001, PAY-REQ-0002, PAY-REQ-0003, PAY-REQ-0004
- **CAP-02 支付事实回传** → PAY-REQ-0005, PAY-REQ-0006, PAY-REQ-0007
- **CAP-03 路由与渠道能力** → PAY-REQ-0008, PAY-REQ-0009
- **CAP-04 支付编排核心** → PAY-REQ-0010, PAY-REQ-0011, PAY-REQ-0012, PAY-REQ-0013
- **CAP-05 渠道适配** → PAY-REQ-0014, PAY-REQ-0015, PAY-REQ-0016, PAY-REQ-0017, PAY-REQ-0018
- **CAP-06 渠道回调入口** → PAY-REQ-0019, PAY-REQ-0020, PAY-REQ-0021
- **CAP-07 退款编排与审批** → PAY-REQ-0022, PAY-REQ-0023
- **CAP-08 争议与订阅** → PAY-REQ-0024, PAY-REQ-0025, PAY-REQ-0026
- **CAP-09 账本与结算** → PAY-REQ-0027, PAY-REQ-0028, PAY-REQ-0029, PAY-REQ-0030, PAY-REQ-0031
- **CAP-10 对账与差错** → PAY-REQ-0032, PAY-REQ-0033, PAY-REQ-0034
- **CAP-11 风险控制** → PAY-REQ-0035, PAY-REQ-0036, PAY-REQ-0037
- **CAP-12 托管收银台与支付链接** → PAY-REQ-0038, PAY-REQ-0039
- **CAP-13 边缘与网络安全** → PAY-REQ-0040
- **CAP-14 运营后台与权限** → PAY-REQ-0041, PAY-REQ-0042
- **CAP-15 安全基础设施** → PAY-REQ-0043, PAY-REQ-0044, PAY-REQ-0045
- **CAP-16 可观测性与运维** → PAY-REQ-0046, PAY-REQ-0047, PAY-REQ-0048
- **CAP-17 治理与合规边界** → PAY-REQ-0049, PAY-REQ-0050, PAY-REQ-0051, PAY-REQ-0052
- **CAP-18 安全供应链与不可变发布** → PAY-REQ-0053
- **CAP-19 移动客户端支付接入** → PAY-REQ-0054

## 禁止流

| ID | 描述 | 强制方式 |
| --- | --- | --- |
| FF-01 | 连接器直接访问业务项目数据库或平台业务表 | NN-01 test:test_b00_module_registry batch:B14 |
| FF-02 | 后台绕过公开领域服务直接修改支付状态 | NN-11 batch:B19 batch:B101 |
| FF-03 | 业务订单明细（商品、库存、履约）落入支付平台数据表 | NN-01 test:test_b01_requirements batch:B13 |
| FF-04 | 以同步回跳、SDK 回调或页面状态作为履约依据 | NN-03 batch:B37 batch:B39 |
| FF-05 | 原始 PAN/CVV/磁道数据进入平台任何服务、日志或存储 | NN-02 test:test_b00_repo_hygiene batch:B104 |
| FF-06 | 跨租户读取支付、账本、对账或导出数据 | NN-09 batch:B31 |
| FF-07 | 未验签或未绑定商户/订单/金额即处理渠道通知 | NN-08 batch:B37 batch:B114 |
| FF-08 | 平台持有资金池、储值余额或进行跨商户清分 | NN-13 test:test_b00_project_config batch:B107 |
| FF-09 | return_url / notify_url / 支付链接指向未登记域名或内网地址 | NN-10 batch:B56 batch:B58 |
| FF-10 | 以人工口头确认替代自动化测试与运行证据 | NN-12 test:test_b00_cli batch:B119 |
