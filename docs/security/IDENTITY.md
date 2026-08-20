<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/identity.json
     Regenerate with: python3 scripts/render-identity.py -->

# 客户、管理员与服务身份（B17）

身份必须是**短期的、有受众的、绑定到持有者的**。只要还存在一张长期、无受众、谁拿到都能用的凭据，前面所有的零信任判定都可以被绕过。

- 允许无绑定 bearer 令牌：**False**
- 禁止的签名算法：`none`、`HS256`、`HS384`、`HS512`
- 令牌绑定：必需=True，方式 `dpop`、`mtls`

> 所有令牌必须绑定到持有者的密钥。无绑定的 bearer 令牌只要被复制就完全可用，而日志、代理、浏览器扩展与错误上报都在复制它。

## OAuth / OIDC

- 允许的流程：`authorization_code`
- 禁止的流程：`implicit`、`resource_owner_password`、`device_code_for_admin`
- PKCE：True（`S256`）；重定向 URI 匹配：`exact`；state=True，nonce=True

> 只允许授权码 + PKCE(S256)，重定向 URI 精确匹配。隐式流把令牌放进 URL，密码流让每个客户端都摸到用户密码——两者在支付场景里都不可接受。重定向 URI 前缀匹配等于开放重定向（NN-10）。

## 撤销

机制 `short_lifetime_plus_revocation_list`，60 秒内全局生效，每次请求都检查：True。

> 撤销 60 秒内全局生效，且每次请求都要检查。一个「等它过期」的撤销不是撤销。

## 发行方

| 发行方 | 用途 | issuer | 受众 | 算法 | 密钥轮换(天) | 令牌上限(分) | 时钟容差(秒) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `customer-idp` | 付款人与商户后台用户 | `https://idp.example.invalid/customer` | `checkout-web`、`merchant-portal` | RS256、ES256 | 30 | 30 | 60 |
| `corporate-idp` | 平台运营与紧急通道 | `https://idp.example.invalid/corp` | `admin-web` | ES256 | 30 | 60 | 60 |
| `workload-ca` | 服务与连接器工作负载 | `spiffe://elmpay.invalid` | `internal-api`、`provider-egress` | ES256 | 1 | 60 | 60 |
| `ci-oidc` | CI 流水线 | `https://ci.example.invalid` | `artifact-registry`、`cloud-control-plane` | RS256 | 30 | 15 | 60 |

- **`customer-idp`**：面向外部用户的 IdP。只允许非对称签名——共享密钥意味着任何一个验证方都能伪造发行方签发的令牌。
- **`corporate-idp`**：企业 IdP，绑定抗钓鱼 MFA（B18）。运营会话最长 60 分钟，与 B16 的上限一致。
- **`workload-ca`**：工作负载证书由平台 CA 签发，每天轮换、60 分钟有效。它不是 IdP 而是 CA，令牌就是那张证书。
- **`ci-oidc`**：CI 用 OIDC 联合换取 15 分钟云凭据，仓库里不存任何长期密钥（NN-07）。

## 令牌

| 令牌 | 类型 | 发行方 | 受众 | 有效期(分) | 绑定 | 可撤销 |
| --- | --- | --- | --- | --- | --- | --- |
| `payer-session` | access | `customer-idp` | `checkout-web` | 30 | `dpop` | 是 |
| `merchant-portal-session` | access | `customer-idp` | `merchant-portal` | 30 | `dpop` | 是 |
| `operator-session` | access | `corporate-idp` | `admin-web` | 60 | `dpop` | 是 |
| `workload-cert` | workload_certificate | `workload-ca` | `internal-api` | 60 | `mtls` | 是 |
| `egress-cert` | workload_certificate | `workload-ca` | `provider-egress` | 60 | `mtls` | 是 |
| `ci-cloud-token` | access | `ci-oidc` | `cloud-control-plane` | 15 | `mtls` | 是 |
| `ci-registry-token` | access | `ci-oidc` | `artifact-registry` | 15 | `mtls` | 是 |

## 主体与身份绑定

| 零信任主体 | 发行方 | 令牌 |
| --- | --- | --- |
| `payer` | `customer-idp` | `payer-session` |
| `merchant-api-client` | `workload-ca` | `workload-cert` |
| `platform-operator` | `corporate-idp` | `operator-session` |
| `service-workload` | `workload-ca` | `workload-cert` |
| `connector-egress` | `workload-ca` | `egress-cert` |
| `ci-pipeline` | `ci-oidc` | `ci-cloud-token` |
| `break-glass` | `corporate-idp` | `operator-session` |

## 账号恢复

| 主体 | 方式 | 冷静期(小时) | 通知渠道 | 不得降级 | 允许仅短信 |
| --- | --- | --- | --- | --- | --- |
| `customer` | email_link_plus_reauth | 0 | email | 是 | 否 |
| `merchant-admin` | email_link_plus_reauth、support_verified_identity | 24 | email、in_app | 是 | 否 |
| `platform-operator` | in_person_verified、hardware_key_reissue | 24 | email、in_app、security_team | 是 | 否 |
| `break-glass` | in_person_verified、hardware_key_reissue | 24 | security_team、on_call、audit_log | 是 | 否 |
| `merchant-finance` | in_person_verified、hardware_key_reissue | 24 | email、in_app、security_team | 是 | 否 |
| `risk-analyst` | in_person_verified、hardware_key_reissue | 24 | security_team、in_app、audit_log | 是 | 否 |

- **`customer`**：付款人恢复必须重新验证，且不得比原来的因素更弱。恢复流程是账号接管最常用的入口。
- **`merchant-admin`**：商户管理员恢复有 24 小时冷静期并全渠道通知——让真正的持有者有机会喊停。
- **`platform-operator`**：运营账号恢复必须线下核验或重新签发硬件密钥。**短信恢复在这里是被明确禁止的**：SIM 交换会让最高权限账号一夜易主。
- **`break-glass`**：紧急通道账号的恢复必须线下核验并重新签发硬件密钥。**这条路径原先根本不存在**——B19 的特权角色清单把它暴露了出来：平台上权限最大的账号，恢复流程却是空白。
- **`merchant-finance`**：商户财务恢复需与原因素同等或更强，并有冷静期与多渠道通知。
- **`risk-analyst`**：风控分析师恢复同样不得降级；能改规则的账号被接管，攻击者可以让自己的交易永远不被拦。

## 服务账号

允许静态密钥：**False**；签发方式 `workload_identity_only`。不存在带静态密码的服务账号。工作负载凭据由 CA 按身份签发、短期、自动轮换。

共 4 个发行方、7 种令牌、6 条恢复路径。
