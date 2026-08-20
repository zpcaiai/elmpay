<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/zero-trust.json
     Regenerate with: python3 scripts/render-zerotrust.py -->

# 零信任访问架构（B16）

不存在「内网所以可信」。每一次访问都要在**这一次**证明身份、证明设备与上下文、命中最小权限策略，并留下可审计的判定记录。

- 默认拒绝：**True**
- 网络位置授予的权限：**无**（这一项必须为空，否则整套设计退化成防火墙）
- 人的会话最长 60 分钟；撤销必须在 60 秒内全局生效
- 工作负载身份：`spiffe_like` over `mtls`，证书最长 60 分钟，长期静态凭据：**禁止**

> 工作负载身份由平台签发、短期有效、自动轮换。长期静态服务账号密码一旦泄露就没有过期这回事（NN-07）。

## 审计

每一次判定（**包括允许**）都要落审计：True；审计不可修改：True。

必备字段：`actor`、`principal_kind`、`resource_class`、`action`、`decision`、`reason`、`policy_version`、`trace_id`、`occurred_at`

> 每一次判定——**包括允许**——都要落审计。只记拒绝的审计，在事后调查里等于没有审计（CTRL-007）。

## 主体

| 主体 | 类别 | 所在区域 | 身份来源 | 凭据 | 有效期(分) | 轮换(天) |
| --- | --- | --- | --- | --- | --- | --- |
| `payer` | human | Z01 用户浏览器/移动端 | `none` | `session_token` | 30 | 0 |
| `merchant-api-client` | machine | Z02 业务项目 | `tenant_api_key` | `http_signature` | 15 | 90 |
| `platform-operator` | human | Z07 管理后台 | `corporate_idp` | `webauthn` | 60 | 0 |
| `service-workload` | workload | Z04 支付核心 | `workload_identity` | `mtls_certificate` | 60 | 1 |
| `connector-egress` | workload | Z05 连接器 | `workload_identity` | `mtls_certificate` | 60 | 1 |
| `ci-pipeline` | workload | Z11 CI/CD | `oidc_federation` | `short_lived_token` | 15 | 0 |
| `break-glass` | human | Z07 管理后台 | `corporate_idp` | `webauthn` | 60 | 0 |

- **`payer`**：付款人不注册也能付款。它的身份是「这次会话」，不是「这个人」，所以它的权限只能是「推进自己这一笔支付」。
- **`merchant-api-client`**：商户服务端。签名有效期 15 分钟，密钥 90 天轮换；密钥本身不落地，由 KMS 短期解密（NN-07）。
- **`platform-operator`**：平台运营人员。抗钓鱼 MFA 是硬要求（B18 落地），会话 60 分钟，高风险操作要求 step-up 并四眼复核（NN-11）。
- **`service-workload`**：服务工作负载。证书 60 分钟有效、每天轮换；**不存在长期静态服务账号密码**。
- **`connector-egress`**：出站到渠道的工作负载。它拿的是出站身份，拿不到支付核心的数据面权限。
- **`ci-pipeline`**：CI 用 OIDC 联合换取 15 分钟令牌，仓库里不存任何云凭据（NN-07）。
- **`break-glass`**：紧急通道。它能跨租户，所以它必须留审计事件、四眼复核并自动过期（NN-11）。

## 访问判定矩阵

| 编号 | 主体 | 资源 | 动作 | 要求 | Step-up | 四眼 | 审计事件 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ZTD-01 | `payer` | `own_payment` | advance | `authenticated_identity`、`authorisation_policy`、`audit_record` | 否 | 否 | `payer.payment_advanced` |
| ZTD-02 | `merchant-api-client` | `tenant_payment` | write | `authenticated_identity`、`authorisation_policy`、`audit_record`、`request_signature`、`tenant_binding` | 否 | 否 | `merchant.payment_write` |
| ZTD-03 | `merchant-api-client` | `tenant_payment` | read | `authenticated_identity`、`authorisation_policy`、`audit_record`、`request_signature`、`tenant_binding` | 否 | 否 | `merchant.payment_read` |
| ZTD-04 | `platform-operator` | `tenant_payment` | read | `authenticated_identity`、`authorisation_policy`、`audit_record`、`device_posture`、`phishing_resistant_mfa`、`justification` | 否 | 否 | `operator.payment_read` |
| ZTD-05 | `platform-operator` | `refund` | approve | `authenticated_identity`、`authorisation_policy`、`audit_record`、`device_posture`、`phishing_resistant_mfa`、`justification` | 是 | 是 | `operator.refund_approved` |
| ZTD-06 | `platform-operator` | `risk_rule` | write | `authenticated_identity`、`authorisation_policy`、`audit_record`、`device_posture`、`phishing_resistant_mfa`、`justification` | 是 | 是 | `operator.risk_rule_changed` |
| ZTD-07 | `break-glass` | `cross_tenant_data` | read | `authenticated_identity`、`authorisation_policy`、`audit_record`、`device_posture`、`phishing_resistant_mfa`、`justification`、`time_bound_session` | 是 | 是 | `breakglass.cross_tenant_read` |
| ZTD-08 | `service-workload` | `owned_table` | write | `authenticated_identity`、`workload_attestation`、`authorisation_policy`、`audit_record` | 否 | 否 | `workload.data_write` |
| ZTD-09 | `service-workload` | `internal_api` | call | `authenticated_identity`、`workload_attestation`、`authorisation_policy`、`audit_record`、`token_audience` | 否 | 否 | `workload.internal_call` |
| ZTD-10 | `connector-egress` | `provider_api` | call | `authenticated_identity`、`workload_attestation`、`authorisation_policy`、`audit_record`、`egress_allowlist` | 否 | 否 | `workload.provider_call` |
| ZTD-11 | `ci-pipeline` | `artifact_registry` | write | `authenticated_identity`、`workload_attestation`、`authorisation_policy`、`audit_record`、`provenance_attestation` | 否 | 否 | `ci.artifact_published` |

- **ZTD-01**：付款人只能推进自己那一笔，且推进结果不作为成功依据（NN-03）——真正的成功来自渠道事件。
- **ZTD-02**：商户只能操作自己租户的支付。租户绑定来自密钥，不来自请求体——让请求体决定租户就是跨租户越权的入口。
- **ZTD-03**：读也要绑定租户。只在写路径上做隔离是最常见的疏漏。
- **ZTD-04**：运营读租户数据必须给出理由，理由进审计。「我看一眼」也要留痕。
- **ZTD-05**：退款审批是资金操作：需要 step-up 且审批人不得是发起人（NN-11）。
- **ZTD-06**：改风控规则等于改所有后续支付的判定，按资金操作对待。
- **ZTD-07**：紧急通道是唯一能跨租户的路径。它必须自动过期，且必须四眼。
- **ZTD-08**：工作负载只能写自己模块拥有的表（与 B14 的 TOPO_TABLE_ACCESS 同一条边界）。
- **ZTD-09**：服务间调用要校验令牌受众。没有受众校验的令牌等于万能钥匙。
- **ZTD-10**：出站必须走白名单。任意出站等于把数据外带通道留给攻击者。
- **ZTD-11**：CI 发布制品必须带来源证明，否则供应链上谁都能塞东西进来。

## 信任边界规则

| 边界 | 名称 | 连接区域 | 双向 mTLS | 要求 |
| --- | --- | --- | --- | --- |
| TB-01 | 付款人到公共边缘 | Z01(untrusted)、Z03(untrusted-ingress) | 否 | `authenticated_identity`、`audit_record` |
| TB-02 | 业务项目到公共边缘 | Z02(semi-trusted)、Z03(untrusted-ingress) | 否 | `request_signature`、`tenant_binding`、`audit_record` |
| TB-03 | 公共边缘到支付核心 | Z03(untrusted-ingress)、Z04(trusted) | 是 | `authenticated_identity`、`authorisation_policy`、`audit_record` |
| TB-05 | 连接器到渠道 | Z05(trusted-egress)、Z06(external) | 是 | `workload_attestation`、`egress_allowlist`、`audit_record` |
| TB-07 | 管理员到后台 | Z07(high-privilege)、Z04(trusted) | 是 | `phishing_resistant_mfa`、`device_posture`、`justification`、`audit_record` |
| TB-08 | 服务到数据层 | Z04(trusted)、Z08(trusted-data) | 是 | `workload_attestation`、`tenant_binding`、`audit_record` |
| TB-10 | 服务到 KMS/HSM | Z04(trusted)、Z10(crypto) | 是 | `workload_attestation`、`audit_record` |
| TB-11 | CI 到生产 | Z11(build)、Z12(infrastructure) | 是 | `provenance_attestation`、`audit_record` |
| TB-04 | 支付核心到连接器 | Z04(trusted)、Z05(trusted-egress) | 是 | `workload_attestation`、`token_audience`、`audit_record` |
| TB-06 | 渠道回调到回调入口 | Z06(external)、Z03(untrusted-ingress) | 否 | `request_signature`、`audit_record` |
| TB-09 | 服务到消息层 | Z04(trusted)、Z09(trusted-data) | 是 | `workload_attestation`、`tenant_binding`、`audit_record` |
| TB-12 | 服务到第三方监控与通知 | Z04(trusted)、Z13(external) | 否 | `workload_attestation`、`egress_allowlist`、`audit_record` |

- **TB-01**：付款人到公共边缘：不要求 mTLS，但边缘必须终止 TLS 并做机器人与限流。
- **TB-02**：业务项目到平台：签名 + 租户绑定，租户来自密钥而不是请求体。
- **TB-03**：公共边缘到支付核心：即使都在「内网」，也要双向 mTLS。这条是零信任与传统边界安全的分水岭。
- **TB-05**：连接器到渠道：出站白名单 + 工作负载证明。
- **TB-07**：管理员到后台：抗钓鱼 MFA + 设备状态 + 操作理由。
- **TB-08**：服务到数据层：工作负载身份 + 租户绑定，与 B13 的强制 RLS 互为纵深。
- **TB-10**：服务到 KMS：只有工作负载身份能取密钥，人拿不到（NN-07）。
- **TB-11**：CI 到制品库：来源证明是供应链的第一道门。
- **TB-04**：支付核心到连接器：两侧都在「内网」，仍然要双向 mTLS 与受众校验。连接器被攻陷时，它拿到的令牌不应该能回头调用支付核心。
- **TB-06**：渠道回调到回调入口：渠道不会用我们的 mTLS，所以这里靠签名 + 时间戳 + 重放窗口。验签之前不做任何业务判断（NN-08）。
- **TB-09**：服务到消息层：消息里带租户，消费方必须能证明自己有权读这个租户的事件。只靠「能连上 broker」就能读全部主题，是最常见的横向移动路径。
- **TB-12**：服务到第三方监控与通知：出站白名单 + 最小化载荷。监控与短信通道是数据外带最常被忽略的出口（NN-14）。

共 7 类主体、11 条访问判定（其中 3 条需要四眼复核）、12 条边界规则。
