<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/key-management.json
     Regenerate with: python3 scripts/render-keys.py -->

# 密钥层级、信封加密与轮换（B20）

密钥不是配置，是**能力**。应用进程从来不「拥有」根密钥或 KEK，它只是在很短的时间里借到一次解密能力。信封加密的意义也不在于「多包了一层」，而在于：数据密钥一条一条独立，密文与它所属的租户、用途、密钥版本**绑定在认证数据里**——把一条密文搬到另一个租户的行上，解密必须失败，而不是解出别人的明文。

## 密钥层级

| 密钥 | 层 | 用途 | 存储 | 算法 | 轮换 | 租户维度 | 被谁包裹 | 保护字段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dek-financial` | dek | tenant_data | envelope | AES-256-GCM | 1 天 | 是 | `kek-tenant-data` | `bank_account_number` |
| `dek-pii` | dek | pii | envelope | AES-256-GCM | 1 天 | 是 | `kek-pii` | `customer_email`、`customer_phone` |
| `dek-provider-credential` | dek | provider_credential | envelope | AES-256-GCM | 1 天 | 否 | `kek-provider-credentials` | — |
| `kek-pii` | kek | pii | kms | AES-256 | 90 天 | 是 | — | — |
| `kek-provider-credentials` | kek | provider_credential | kms | AES-256 | 90 天 | 否 | — | — |
| `kek-tenant-data` | kek | tenant_data | kms | AES-256 | 90 天 | 是 | — | — |
| `root-hsm` | root | key_wrapping | hsm | AES-256 | 730 天 | 否 | — | — |

- **`root-hsm`**：根密钥，只包裹 KEK，不直接加密任何业务数据。
- **`kek-provider-credentials`**：包裹所有渠道私钥与 API 凭据的数据密钥。
- **`kek-tenant-data`**：每租户一把 KEK：销毁它就等于**密码学销毁**该租户的全部数据，这是租户下线时唯一可验证的删除方式。
- **`kek-pii`**：个人信息字段的 KEK，与业务数据 KEK 分开，便于单独轮换与单独审计。
- **`dek-provider-credential`**：渠道凭据的数据密钥，一条凭据一把。
- **`dek-pii`**：个人信息字段的数据密钥。
- **`dek-financial`**：收款账号等资金相关字段的数据密钥。

## 信封加密

- 数据密钥算法：`AES-256-GCM`，包裹算法：`AES-256-GCM`
- 粒度：每 record 一把；明文数据密钥存活 300 秒
- nonce：12 字节，禁止重用：是
- AAD 绑定：`tenant_id`、`purpose`、`key_id`

每条记录一把数据密钥；数据密钥由 KEK 包裹后与密文同存，明文数据密钥只在内存里存活 300 秒。AAD 绑定租户、用途与密钥版本——**这是防止密文在租户之间搬家的唯一机制**。GCM 的 nonce 一旦重用，同一把密钥下的两条密文可以互相抵消出明文，因此 nonce 重用被明确禁止。

## HSM

- 根密钥必须在 HSM：是；FIPS 140 等级：3
- 可导出：否；法定人数：2/3

根密钥只在 HSM 内部存在，不可导出；根密钥操作需要 2/3 法定人数，避免任何单人（包括平台运营）独自动用最高密钥。

## 轮换

- 根密钥 730 天、KEK 90 天、数据密钥每条记录一把
- 重叠期 7 天；策略：`rewrap_data_keys`
- 紧急轮换：4 小时内

KEK 轮换只需重新包裹数据密钥，不必重写业务数据——这也是信封加密真正的运维价值。轮换有 7 天重叠期，旧版本仍可解密；泄露时必须在 4 小时内完成紧急轮换。

## 渠道与身份提供方密钥

| 提供方 | 密钥材料 | 签名算法 | 归属密钥 |
| --- | --- | --- | --- |
| `alipay` | hsm_backed | RSA-2048-PSS | `kek-provider-credentials` |
| `apple_pay` | hsm_backed | ECDSA-P256 | `kek-provider-credentials` |
| `ci-oidc` | external_jwks | RS256 | `kek-provider-credentials` |
| `corporate-idp` | external_jwks | RS256 | `kek-provider-credentials` |
| `customer-idp` | external_jwks | RS256 | `kek-provider-credentials` |
| `merchant-authorization-server` | external_jwks | RS256 | `kek-provider-credentials` |
| `paypal` | envelope_encrypted | none | `kek-provider-credentials` |
| `stripe` | envelope_encrypted | none | `kek-provider-credentials` |
| `wechat` | hsm_backed | RSA-2048-PSS | `kek-provider-credentials` |
| `workload-ca` | hsm_backed | ECDSA-P256 | `kek-provider-credentials` |

- **`wechat`**：微信支付商户私钥由 HSM 托管，应用只能请求签名，拿不到私钥本身。
- **`alipay`**：支付宝应用私钥同上。
- **`stripe`**：Stripe 使用 API 密钥而非签名私钥，凭据以信封加密存储，用完即弃。
- **`paypal`**：PayPal 同上。
- **`apple_pay`**：Apple Pay 支付处理私钥由 HSM 托管，用于解密支付令牌。
- **`customer-idp`**：外部身份提供方的验签公钥来自 JWKS，本平台不持有其私钥。
- **`merchant-authorization-server`**：商户 OAuth2 authorization server 的 at+jwt 验签公钥仅通过轮换 JWKS 获取，本平台不持有其签发私钥。
- **`corporate-idp`**：企业身份提供方的验签公钥同样来自 JWKS；本平台不持有其私钥，也就无从泄露。
- **`workload-ca`**：工作负载身份 CA 的签发私钥必须在 HSM 内：它能签出任何服务身份。
- **`ci-oidc`**：CI 的 OIDC 令牌由外部签发。

## 销毁（密码学销毁）

租户下线时销毁其 KEK：备份里的密文从此不可解，这是唯一能在有备份的系统里被验证的删除。

## 禁止项

- 算法：`DES`、`3DES`、`RC4`、`AES-ECB`、`MD5`、`SHA1`、`none`
- RSA 最小长度：2048 位

ECB 模式泄露明文结构；MD5/SHA1 已不具备抗碰撞性；任何硬编码密钥材料都等同于公开。
