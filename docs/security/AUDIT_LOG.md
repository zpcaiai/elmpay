<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/audit-log.json
     Regenerate with: python3 scripts/render-audit.py -->

# 不可抵赖审计与防篡改日志（B23）

审计日志的价值不在于「记了」，而在于**事后没人能改**。一条能被改的记录，在争议里等于没有记录。因此这里有三层：每条记录进入**按租户的哈希链**（改一条、删一条、换顺序都会断链）；链头定期被**签名锚定**（否则截断尾部无法发现）；负载支持**密码学删除**（个人信息可以消失，而记录本身仍然可验证）。第三层是唯一能同时满足「不可抵赖」和「被遗忘权」的做法。

## 哈希链

- 算法：`SHA-256`；按租户分链：是
- 覆盖前一条哈希与序号：是 / 是
- 规范化序列化：`json_sorted_keys_utf8`

哈希覆盖序号与前一条哈希：改一条会让它之后的每一条都对不上，删一条会让序号出现空洞。规范化序列化是必需的——同一条记录序列化成两种字节，哈希就不再是同一条记录的哈希。

## 锚定

- 间隔：60 分钟（**这就是可被否认窗口的大小**）
- 签名密钥：`kek-provider-credentials`；见证方：`external_timestamp_authority`
- 锚点保留：3650 天

哈希链自己**发现不了尾部被截断**：把最后 N 条连同链头一起删掉，剩下的链依然自洽。锚点是唯一的解法——每小时把链头签名并交给外部时间戳机构，于是可被否认的窗口最多一小时（残余风险见 §8）。

## 事件类别

| 类别 | 来源 | 保留 | 含个人信息 |
| --- | --- | --- | --- |
| `authz.decision` | authorization | 2555 天 | 否 |
| `authz.elevation` | authorization | 2555 天 | 否 |
| `config.change` | platform | 3650 天 | 否 |
| `data.access` | platform | 2555 天 | 是 |
| `identity.authentication` | identity | 1095 天 | 是 |
| `key.use` | kms | 2555 天 | 否 |
| `money.movement` | ledger | 3650 天 | 否 |

- **`authz.decision`**：每一次授权判定，允许与拒绝都记。
- **`authz.elevation`**：限时提权的申请、批准、使用与到期收回。
- **`money.movement`**：资金动作，保留十年。
- **`key.use`**：密钥使用与轮换、销毁。
- **`identity.authentication`**：登录、MFA、恢复流程；含个人信息，因此负载可被密码学删除。
- **`config.change`**：平台配置变更。配置能关掉其它所有控制，因此它的变更记录必须比配置本身活得久。
- **`data.access`**：对个人信息与资金数据的读取。

## 必须留痕的动作

`config.write`、`cross_tenant_data.read`、`ledger.adjust`、`payout.approve`、`payout_account.write`、`reconciliation.approve`、`refund.approve`、`risk_decision.override`、`risk_rule.write`

## 记录字段

- 必需：`event_id`、`occurred_at`、`tenant_id`、`actor`、`actor_role`、`action`、`resource`、`decision`、`rule_version`、`request_digest`
- 禁止：`card_pan`、`card_cvv`、`password`、`authorization_header`

五个 W 加两样东西：判定用的规则版本，以及这次请求的摘要。没有规则版本，事后只能回答「现在的规则会不会放行」，回答不了「当时为什么放行」。

## 存储

存储层只允许追加；应用的凭据不能删除审计记录——能删日志的人和被日志监督的人必须是两拨人。

## 删除与被遗忘权

个人信息负载单独加密；删除时销毁负载密钥，保留内容哈希。于是「这条记录存在、内容未被改动」仍可证明，而内容本身已不可读——这是同时满足不可抵赖与被遗忘权的唯一做法。

## 时间

时间来自可信时间源；同一条链上的序号必须单调递增。允许时钟有偏差，但不允许顺序被时钟决定。

## 访问

审计读取本身要被审计。审计员不可提权——能改自己所审计对象的人不是审计员。

## 验证

验证流程必须被定期演练，且验证器必须能被独立方运行——只有我们自己能验证的链，在争议中说服不了任何人。
