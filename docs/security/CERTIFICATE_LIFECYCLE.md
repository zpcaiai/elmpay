<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/certificates.json
     Regenerate with: python3 scripts/render-certs.py -->

# 密钥、证书与域名生命周期（B21）

证书与密钥的事故几乎从不是「被破解」，而是**到期**、**换不动**和**撤销没生效**。因此这里管的不是算法，而是**时间**：每一份材料都有到期日、有提前量足够的告警、有新旧并存的重叠期、有一条被演练过的撤销与恢复路径。一条不能在旧材料仍然有效时就完成切换的轮换流程，等于没有轮换流程。

## 生命周期阶段

`generate` → `distribute` → `activate` → `overlap` → `rotate` → `revoke` → `recover`

## 材料

| 材料 | 类型 | 主体 | 签发方 | 有效期 | 提前续期 | 重叠期 | 自动续期 | 撤销方式 | 负责人 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `apple-pay-processing` | signing_key | `apple_pay-processing` | provider | 365 天 | 60 天 | 30 天 | 人工 | provider_console | payments-integration |
| `edge-tls` | tls_certificate | `pay.example.invalid` | public_ca | 90 天 | 31 天 | 7 天 | ✅ | ocsp_must_staple | platform-security |
| `internal-mtls` | tls_certificate | `*.internal.pay.example.invalid` | workload-ca | 7 天 | 3 天 | 1 天 | ✅ | short_lived | platform-security |
| `provider-signing-alipay` | signing_key | `alipay-app` | provider | 365 天 | 60 天 | 30 天 | 人工 | provider_console | payments-integration |
| `provider-signing-wechat` | signing_key | `wechat-merchant` | provider | 365 天 | 60 天 | 30 天 | 人工 | provider_console | payments-integration |
| `token-signing` | signing_key | `platform-tokens` | self | 90 天 | 31 天 | 7 天 | ✅ | jwks_removal | platform-security |
| `webhook-verification` | verification_key | `provider-webhooks` | provider | 180 天 | 60 天 | 14 天 | ✅ | key_set_rotation | payments-integration |
| `workload-ca-root` | ca_certificate | `workload-ca` | self | 1825 天 | 365 天 | 180 天 | 人工 | trust_store_rollout | platform-security |

- **`edge-tls`**：对外 TLS 证书，ACME 自动续期。90 天有效期配 30 天提前量：即使续期连续失败两周，仍有人来得及处理。
- **`internal-mtls`**：服务间 mTLS 证书，7 天有效期。短寿命本身就是撤销机制：不需要 CRL 也能在一周内自然失效。
- **`provider-signing-wechat`**：渠道签名私钥由渠道方签发，只能人工轮换，因此提前量与重叠期都要更长：**重叠期内新旧密钥都必须能验签**，否则切换瞬间会拒绝所有回调。
- **`provider-signing-alipay`**：支付宝应用私钥同样由渠道方签发、人工轮换。到期未换的后果不是「降级」而是**全部支付请求签名失败**，因此提前量与重叠期与微信一致。
- **`webhook-verification`**：验签公钥集合。渠道方可能**不打招呼就换密钥**，因此必须支持同时持有多把公钥并按 key id 选择。
- **`workload-ca-root`**：工作负载 CA 根证书。轮换要提前一年开始，因为**信任库的分发比证书本身慢得多**：所有节点都信任新根之前，不能停用旧根。
- **`token-signing`**：平台自签令牌的签名密钥（B17）。JWKS 中新旧公钥并存 7 天，保证在途令牌不会因轮换而失效。
- **`apple-pay-processing`**：Apple Pay 支付处理私钥，用于解密支付令牌。它由 HSM 托管（B20），但**托管不等于有到期日**——这条记录就是为了让它有。

## 域名

| 域名 | 用途 | 注册商锁 | DNSSEC | CAA | 提前续费 | 负责人 |
| --- | --- | --- | --- | --- | --- | --- |
| `api.pay.example.invalid` | merchant_api | ✅ | ✅ | public_ca | 90 天 | platform-security |
| `internal.pay.example.invalid` | internal | ✅ | ✅ | workload-ca | 90 天 | platform-security |
| `pay.example.invalid` | checkout | ✅ | ✅ | public_ca | 90 天 | platform-security |

- **`pay.example.invalid`**：收银台主域名。注册商锁 + DNSSEC + CAA：域名被劫持时，攻击者能签出「合法」证书，TLS 就再也证明不了任何事。
- **`api.pay.example.invalid`**：商户 API 域名。
- **`internal.pay.example.invalid`**：内部域名，CAA 只允许自建 CA 签发——公共 CA 不应该能为它签证书。

## 告警

- 通道：`on_call`、`security_team`、`ticket`
- 到期告警阈值：剩余寿命的 34%
- 连续 2 次自动续期失败即升级人工
- 非预期签发方告警：是；CT 日志监控：是

到期告警必须在「剩余时间 < 提前量」时触发，并在连续两次自动续期失败后升级为人工处理。同时监控 CT 日志：任何为我们的域名签出的、不是我们申请的证书，都是事故信号。

## 灾难恢复

- 已演练：是，每 180 天一次
- 恢复目标：4 小时内
- CA 离线备份：是；需法定人数：是

灾难恢复必须被**演练过**：一条从未走过的恢复流程在事故当天是不可信的。CA 材料有离线备份，恢复需要法定人数，目标 4 小时内恢复签发能力。

## 禁止项

边缘不得使用自签证书；短寿命材料不得依赖人工续期（7 天有效期 + 人工续期 = 每周一次的停机赌博）；生产与非生产不得共用密钥。
