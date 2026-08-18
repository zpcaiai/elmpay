
# 渠道能力矩阵

| 能力 | 微信 | 支付宝 | Stripe | PayPal | Apple Pay |
|---|---|---|---|---|---|
| 即时支付 | 是 | 是 | 是 | 是 | 经 PSP |
| 延迟捕获 | 依产品 | 依产品 | 是 | 是 | 经 PSP |
| 部分退款 | 是 | 是 | 是 | 是 | 经 PSP |
| 周期计费 | 委托扣款产品 | 周期扣款产品 | 是 | 是 | Merchant Token/PSP |
| 争议/拒付 | 钱包投诉/渠道流程 | 渠道流程 | 是 | 是 | 卡网络/PSP |
| Webhook/通知 | APIv3 通知 | 异步通知 | Events | Webhooks | PSP/客户端 token |
| 账单 | 交易+资金 | 账单 | Balance/Reports | Reports/API | PSP |

具体能力必须按商户账户、地区、币种和合同动态配置，不得把本表当作渠道承诺。
