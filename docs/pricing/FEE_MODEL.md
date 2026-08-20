<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/fee-model.json
     Regenerate with: python3 scripts/render-fees.py -->

# 费率、成本、佣金与计量模型（B29）

**账面模型不是资金事实**。我们算出来的费用是一个估计，真正被扣掉多少要等渠道结算报告说了算；两者不一致时唯一正确的动作是**开一条对账项**，而不是把账面悄悄改成渠道说的数——后者会让「我们以为收了多少」这个问题永远无法回答。其余三条同样是被现实教出来的：**税不是收入**，它是代收代缴，混进收入口径就是虚增；**分账各方之和必须等于总额**，一分钱的余数也必须有明确归属，「四舍五入后差一分」是对账系统里最常见也最难查的差异；**费用币种必须等于支付币种**，跨币种必须有显式汇率记录，隐式换算会把汇率损益藏进费用里。

## 费用类别

| 类别 | 是收入 | 向商户收取 | 代收代缴 | 说明 |
| --- | --- | --- | --- | --- |
| `provider_cost` | 否 | 是 | 否 | 渠道成本：渠道实际收走的钱，账面值是估计，以结算报告为准。 |
| `platform_service_fee` | 是 | 是 | 否 | 平台服务费：唯一属于平台收入的类别。 |
| `tax` | 否 | 是 | 是 | 税费：代收代缴，**不得计入收入**；混进收入口径就是虚增。 |
| `internal_cost` | 否 | 否 | 否 | 内部成本：风控、客服、资金占用等，**不向商户收取**，只用于毛利口径。 |

## 舍入

- 方式：`half_up`，单位：minor
- 各部分之和必须等于总额：是
- 余数归属：`platform`

舍入方式必须写死并可复现；余数必须有归属。把余数留给「谁先算谁拿」是对账差异的经典来源——它每天只差一分钱，但一年之后没有人能解释那笔钱去了哪。

## 费率表

| 编号 | 类别 | 计算基数 | 渠道 | 方式 | 地区 | 币种 | 百分比(基点) | 固定(最小单位) | 下限 | 封顶 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `alipay_cn_cost` | `provider_cost` | `payment` | `alipay` | `alipay` | CN | CNY | 60 | 0 | — | — |
| `applepay_cn_cost` | `provider_cost` | `payment` | `apple_pay` | `apple_pay` | CN | CNY | 15 | 0 | — | — |
| `internal_risk_cn` | `internal_cost` | `payment` | `wechat` | `wechat_pay` | CN | CNY | 5 | 0 | — | — |
| `paypal_eu_cost` | `provider_cost` | `payment` | `paypal` | `paypal_wallet` | EU | EUR | 290 | 35 | — | — |
| `platform_cn` | `platform_service_fee` | `payment` | `wechat` | `wechat_pay` | CN | CNY | 30 | 0 | 1 | 500000 |
| `platform_eu` | `platform_service_fee` | `payment` | `stripe` | `card` | EU | EUR | 30 | 0 | 1 | 500000 |
| `stripe_eu_cost` | `provider_cost` | `payment` | `stripe` | `card` | EU | EUR | 140 | 25 | — | — |
| `stripe_hk_cost` | `provider_cost` | `payment` | `stripe` | `card` | HK | HKD | 340 | 235 | — | — |
| `stripe_sg_cost` | `provider_cost` | `payment` | `stripe` | `card` | SG | SGD | 340 | 50 | — | — |
| `tax_eu_vat` | `tax` | `platform_service_fee` | `stripe` | `card` | EU | EUR | 2000 | 0 | — | — |
| `wechat_cn_cost` | `provider_cost` | `payment` | `wechat` | `wechat_pay` | CN | CNY | 60 | 0 | — | — |

- **`wechat_cn_cost`**：微信支付境内费率 0.6%。
- **`alipay_cn_cost`**：支付宝境内费率 0.6%。
- **`stripe_eu_cost`**：欧盟卡：1.4% + €0.25，典型的百分比加固定。
- **`stripe_sg_cost`**：新加坡卡费率更高。
- **`stripe_hk_cost`**：香港卡。
- **`paypal_eu_cost`**：PayPal 欧盟。
- **`platform_cn`**：平台服务费 0.3%，有下限与封顶：没有封顶的百分比费在大额交易上不合理。
- **`platform_eu`**：欧盟平台服务费。
- **`tax_eu_vat`**：欧盟增值税按平台服务费计征，代收代缴。
- **`internal_risk_cn`**：内部风控成本估算，不向商户收取。
- **`applepay_cn_cost`**：境内 Apple Pay 直连的通道成本；门禁查出它原本没有费率表——一个有绑定却没有成本口径的渠道，每一笔都在记一个未知成本。

## 结算

- 账面值是估计：是
- 权威来源：`provider_settlement_report`
- 不一致时开对账项：是
- 允许静默覆盖：**否**
- 容差：0；最长结算滞后：35 天

账面值永远标记为估计，直到结算报告到达。差异**开对账项**而不是覆盖账面：覆盖之后，「我们当初以为收多少」这个问题就永远查不出来了。容差为 0：金额是整数，任何差异都是真差异。

## 分账

- 参与方：`merchant`、`platform`、`provider`、`authority`
- 各方之和必须等于总额：是
- 余数归：`platform`

四方之和必须精确等于总额；余数归平台，且这条必须写下来而不是靠实现顺序决定。

## 币种

- 费用币种等于支付币种：是
- 允许隐式换算：**否**
- 汇率记录字段：`rate`、`quoted_at`、`source`

隐式换算会把汇率损益藏进费用里，让费率看起来忽高忽低而没人知道为什么。跨币种必须有显式汇率记录。

## 计量

- 事件键：`payment_id`
- 幂等：是；可重算：是
- 保留：1825 天

计量事件按支付 ID 幂等：渠道重发、内部重试、补数任务都可能重复投递同一笔。可重算意味着任何一天的计量都能从原始事件重新推导，而不是只能相信当时写下的汇总。

审计事件类别：`money.movement`（见 B23）。
