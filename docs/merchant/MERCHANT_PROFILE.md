<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/merchant-profile.json
     Regenerate with: python3 scripts/render-merchant.py -->

# 商户资料与 KYB 元数据（B25）

本平台**不是持牌核验机构**，因此这里管理的是「资料与状态」，不是「核验结论」。最重要的一条规则由此而来：我们自己的记录**永远不能把状态写成「已核验」**，除非它引用了一个外部持牌机构的核验决定（机构、决定编号、日期、有效期）。其余三条同样是被现实教出来的：KYB 材料**会过期**（核验是持续状态不是一次性事件）、**改收款账户与改实际控制人必须触发重新核验**（这是接管商户最常用的两步）、以及**高风险等级的批准不能由一个人做完**。

## 核验：谁说了算

- 平台是持牌核验机构：**否**
- 核验决定必须引用外部机构：是
- 必需字段：`authority`、`decision_reference`、`decided_at`、`valid_until`
- 核验结论最长有效期：730 天
- 允许商户自证的字段：`display_name`、`support_contact`、`website`

核验决定必须来自外部持牌机构并带有效期。允许商户自证的只有不影响资金与合规判断的展示信息——把「自己填的」和「被核验的」混在同一个字段里，是这个领域最常见的欺骗面。

## 主体类型与所需材料

| 主体 | 材料 | 说明 |
| --- | --- | --- |
| `company` | `business_licence`、`ubo_declaration`、`director_identity`、`bank_account_proof` | 有限公司：需要营业执照、实际控制人声明、董事身份、收款账户证明。 |
| `sole_trader` | `business_licence`、`director_identity`、`bank_account_proof` | 个体工商户：没有股权结构，但仍需要经营主体证明与账户证明。 |
| `individual` | `director_identity`、`bank_account_proof` | 个人收款：材料最少，因此限额也最低。 |

## 材料与有效期

| 材料 | 证明什么 | 有效期（天） | 含个人信息 | 出具方 |
| --- | --- | --- | --- | --- |
| `bank_account_proof` | 收款账户属于该主体 | 180 | 是 | bank |
| `business_licence` | 法人主体存在且经营范围合法 | 365 | 否 | registry |
| `ubo_declaration` | 谁最终控制这家公司 | 365 | 是 | merchant |
| `director_identity` | 签署人是本人 | 730 | 是 | government |

- **`business_licence`**：营业执照有年检与吊销，一年一查是下限而不是保守。
- **`ubo_declaration`**：实际控制人声明由商户提供，因此**必须与外部核验交叉**；只信声明等于不做 KYB。
- **`director_identity`**：身份证件本身会过期，过期即视为缺失。
- **`bank_account_proof`**：**这是最短的有效期**：收款账户是资金的去向，也是接管商户后第一个被改的东西。

## 实际控制人（UBO）

- 持股门槛：25%
- 穿透层数上限：5
- 需要身份证件：是
- 需要名单筛查：是

持股 25% 以上视为实际控制人，且必须穿透最多五层股权。只看第一层股东，等于让任何人用一个空壳挡住自己。

## 名单筛查

- 名单：`sanctions`、`pep`、`adverse_media`
- 重筛周期：90 天
- 命中转人工：是
- 命中后自动放行：**否**

命中制裁名单**永远不能自动放行**，也不能自动拒绝：自动拒绝会把大量同名误伤，因此必须转人工，并记录判断理由。

## 经营类目

| 类目 | 风险 | 是否承接 | 说明 |
| --- | --- | --- | --- |
| `retail_goods` | low | ✅ | 实物零售。 |
| `digital_services` | medium | ✅ | 数字服务，退款争议率高于实物。 |
| `travel` | high | ✅ | 旅游：预付款与交付间隔长，破产时退款风险由平台承担。 |
| `crypto_exchange` | prohibited | ❌ | 本平台不承接。 |
| `adult_content` | prohibited | ❌ | 本平台不承接。 |
| `unlicensed_gambling` | prohibited | ❌ | 本平台不承接。 |

## 经营地区与结算币种

| 地区 | 结算币种 | 需本地主体 | 说明 |
| --- | --- | --- | --- |
| `CN` | `CNY` | 是 | 境内经营需要境内主体。 |
| `HK` | `HKD`、`USD` | 否 | 香港：可用美元结算。 |
| `SG` | `SGD`、`USD` | 否 | 新加坡。 |
| `EU` | `EUR` | 是 | 欧盟：本地主体与本地结算账户。 |

## 风险等级

| 等级 | 日限额（最小单位） | 单笔限额 | 结算延迟（天） | 批准人数 |
| --- | --- | --- | --- | --- |
| `low` | 50000000 | 5000000 | 1 | 1 |
| `medium` | 20000000 | 2000000 | 3 | 1 |
| `high` | 5000000 | 500000 | 7 | 2 |

- **`low`**：低风险：T+1 结算。
- **`medium`**：中风险：结算延后，给争议留出时间。
- **`high`**：高风险：限额压低、结算延后到七天，**且批准需要两个人**。

## 重大变更

| 变更 | 所需权限 | 需重新核验 | 暂停结算 | 说明 |
| --- | --- | --- | --- | --- |
| `payout_account_change` | `payout_account.write` | 是 | 是 | 改收款账户：接管商户后的第一步，因此必须重新核验并暂停结算直到通过。 |
| `ubo_change` | `config.write` | 是 | 否 | 实际控制人变更：主体没变，但「谁在控制」变了。 |
| `legal_name_change` | `config.write` | 是 | 否 | 法人名称变更需重新取证。 |
| `country_change` | `config.write` | 是 | 是 | 经营国家变更会改变适用法域与结算币种。 |
| `category_change` | `config.write` | 是 | 否 | 经营类目变更可能落入禁止类目。 |

## 留存

- 离场后保留：1825 天
- 按声明目的最小化：是
- 材料加密存储：是

KYB 材料在商户离开后仍需按监管要求保留五年；保留不等于可读——材料加密存储，读取受 B19 字段规则约束。

审计事件类别：`config.change`（见 B23）。

## 申诉

- 可申诉：是
- 决定必须说明理由：是
- 复核人须不同于原判人：是
- 答复时限：15 天

拒绝必须给出理由并可申诉，复核人不能是原判人。一个不能被申诉的自动拒绝，在监管与商业上都站不住。
