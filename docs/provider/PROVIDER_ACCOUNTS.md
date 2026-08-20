<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/provider-accounts.json
     Regenerate with: python3 scripts/render-accounts.py -->

# 商户渠道账户与凭证绑定（B26）

渠道回调**永远不能靠猜来归属租户**。绑定关系是唯一的映射来源，而映射的键必须是渠道自己在回调里原样回传的标识；当一个回调无法被唯一归属时，正确的动作是**隔离并告警**，不是「取最像的那一个」——猜错一次，就是把 A 商户的钱记到 B 商户名下。由此派生的另外三条同样是被现实教出来的：凭证**按租户、项目、环境、渠道四维隔离且永不共享**（一把共享密钥意味着一次泄露波及所有人）；绑定**只能由一次真实的往返验证激活**，不是填完表单就算通；以及**停用不等于断开回调**——停用停止发起新支付，但在途交易的回调必须继续接收，否则平台会丢掉自己已经收过钱的证据。

## 绑定是什么

- 身份维度：`tenant_id`、`project_id`、`environment`、`provider`、`provider_merchant_id`
- 唯一键：`tenant_id`、`project_id`、`environment`、`provider`
- 不可变字段：`tenant_id`、`project_id`、`environment`、`provider`、`provider_merchant_id`
- 一个绑定一份凭证：是

绑定的身份四维加上渠道商户号；这五项一旦写入不可修改——可变的绑定等于可迁移的资金去向，而迁移不会留下任何痕迹。要改，只能吊销旧绑定再新建一条，历史因此永远可解释。

## 渠道

| 渠道 | 凭证类型 | 密钥 | 环境 | 结算币种 | 回调归属字段 | 轮换（天） |
| --- | --- | --- | --- | --- | --- | --- |
| `alipay` | signing_key | `kek-provider-credentials` | live、test | CNY、HKD | `provider_merchant_id` | 90 |
| `apple_pay` | decryption_key | `kek-provider-credentials` | live、test | USD、EUR、GBP、CNY、HKD | `provider_merchant_id` | 90 |
| `paypal` | api_key | `kek-provider-credentials` | live、test | USD、EUR、GBP | `endpoint_id` | 90 |
| `stripe` | api_key | `kek-provider-credentials` | live、test | USD、EUR、GBP、SGD、HKD | `endpoint_id` | 90 |
| `wechat` | signing_key | `kek-provider-credentials` | live、test | CNY、HKD | `provider_merchant_id` | 90 |

- **`wechat`**：微信支付：商户私钥在 HSM 里，应用只能请求签名；回调用商户号归属。
- **`alipay`**：支付宝：应用私钥同样由 HSM 托管。
- **`stripe`**：Stripe 用 API 密钥而不是签名私钥，且回调按 endpoint 区分——因此归属键是 endpoint 而不是商户号：**每个绑定必须有自己的 endpoint**。
- **`paypal`**：PayPal 同上。
- **`apple_pay`**：Apple Pay：支付处理私钥用于解密令牌，同样在 HSM 内。

## 凭证

- 存储：envelope_encrypted
- 明文落盘：否；明文进日志：否
- 解密租约上限：300 秒
- 轮换：每 90 天，重叠期 7 天
- 共享：租户间禁止、环境间禁止、项目间禁止

凭证解密是**短租约**：拿到明文的窗口以秒计，过期即失效，因为一个长期驻留内存的渠道私钥等于一个长期可被导出的私钥。轮换必须有重叠期——没有重叠期的轮换会在切换的瞬间丢掉正在途中的回调，而那些回调正是平台证明自己收过钱的唯一凭据。

## 回调

- 必须验签：是
- 归属必须确定：是
- 歧义时猜测：**禁止**
- 无法归属时隔离：是
- 跨租户投递：禁止
- 回跳页作为支付证据：**否**
- 接受时窗：300 秒；幂等键字段：`provider_event_id`

回调必须验签、必须能被唯一归属、必须带渠道事件号做幂等。客户端回跳页**不是**支付成功的证据（NN-01）：它由付款人的浏览器发起，任何人都能构造。

## 隔离区

- 保留：30 天；告警：必须
- 自动重放：**禁止**
- 人工重放必须给出归属：是

无法归属的回调进隔离区并告警。**不允许自动重放**——自动重放一个归属不明的资金事件，等于让系统替人做那个它做不了的判断。人工重放必须先给出明确归属。

## 激活

- 需要真实测试交易：是
- 需要回调往返：是
- 需要验签通过：是

激活的条件是**一次真实的往返**：发起一笔测试交易、收到渠道回调、验签通过。填完表单就置为可用，等于把第一次真实支付当成联调。

## 生命周期

`pending` → `active` → `suspended` → `revoked`

| 从 | 到 | 前置条件 | 说明 |
| --- | --- | --- | --- |
| `pending` | `active` | `test_transaction_settled`、`callback_roundtrip_verified` | 只有往返验证通过才能激活。 |
| `active` | `suspended` | `reason`、`actor` | 停用停止发起新支付，但不断开回调。 |
| `suspended` | `active` | `reason`、`actor`、`second_approver` | 恢复需要第二个人：单人恢复等于单人推翻风控的决定。 |
| `suspended` | `revoked` | `in_flight_settled`、`credential_destroyed` | 吊销前必须先把在途交易结清，再销毁凭证。 |
| `active` | `revoked` | `in_flight_settled`、`credential_destroyed`、`second_approver` | 直接吊销同样要先结清在途，且需要复核。 |

## 各状态下还能做什么

| 状态 | 发起支付 | 接收回调 | 退款 | 结算 | 轮换凭证 |
| --- | --- | --- | --- | --- | --- |
| `pending` | — | ✅ | — | — | ✅ |
| `active` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `suspended` | — | ✅ | ✅ | ✅ | ✅ |
| `revoked` | — | — | — | — | — |

- **`pending`**：待验证：只能收到自己发起的那笔测试交易的回调。
- **`active`**：已验证：发起、回调、退款、结算、轮换全开；这是唯一可以接受真实支付的状态。
- **`suspended`**：停用停止新支付；**回调、退款、结算必须继续**——在途的钱已经离开付款人，断开回调只会让平台丢掉自己收过钱的证据。
- **`revoked`**：吊销后凭证已销毁，什么都做不了；此前的在途交易在吊销前已结清。

## 禁止

- `shared_credential_across_tenants`：禁止
- `shared_credential_across_environments`：禁止
- `credential_in_source_or_ci`：禁止
- `callback_without_signature`：禁止
- `attribution_by_amount_or_time`：禁止

最后一条最容易被当成「聪明的兜底」：用金额加时间去猜归属。它在测试环境永远有效，在生产环境会在第一个并发相同金额的时刻把两笔钱记反。

轮换权限：`config.write`（见 B19）；审计事件类别：`config.change`（见 B23）。
