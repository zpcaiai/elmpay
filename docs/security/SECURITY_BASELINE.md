<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/security-baseline.json
     Regenerate with: python3 scripts/render-baseline.py -->

# 安全基线：ASVS / API Security / MASVS（B22）

一条没有被任何规则或测试执行的安全要求，等于一句话。所以这里不是一张对照表，而是一份**可执行的映射**：每一条要求要么指向一个真实存在、真实会触发的门禁规则码，要么指向一个真实存在的测试方法，要么被**明确记为缺口**（带负责人和复核批次）。门禁会去核对这三件事——引用一个不存在的规则码，本身就是一条不合格。

## 覆盖

- 适用要求：31 条；已由规则或测试执行：27 条 （87%）
- 明确记录的缺口：8 条（上限 8）

覆盖率的分母是**适用的**要求；不适用的条目不能靠改 applicability 来提高分子。缺口有上限，因为「记为缺口」如果没有上限，它就是「忽略」的另一个写法。

## 标准

| 标准 | 版本 | 说明 |
| --- | --- | --- |
| `API` | 2023 | OWASP API Security Top 10。 |
| `ASVS` | 4.0.3 | OWASP 应用安全验证标准，本平台按 L2 要求。 |
| `MASVS` | 2.0 | OWASP 移动应用安全验证标准；本平台目前没有自有移动端，相关条目一律记为缺口而不是「符合」。 |

## 映射

| 要求 | 标准 | 级别 | 适用面 | 执行方式 | 引用 |
| --- | --- | --- | --- | --- | --- |
| `API-01` | API | L2 | api | test | `tools/tests/test_b19_authz.py::AuthzDecisionFunction::test_object_ownership_is_checked_even_inside_the_right_tenant` |
| `API-02` | API | L2 | api | gate_rule | `ID_FLOW`、`ID_FORBIDDEN_ALGORITHM` |
| `API-03` | API | L2 | api | gate_rule | `AUTHZ_FIELD_MASK`、`AUTHZ_FIELD_PAN_READABLE` |
| `API-04` | API | L2 | api | accepted_gap | — |
| `API-05` | API | L2 | api | gate_rule | `AUTHZ_ROLE_PERMISSION_UNKNOWN`、`MFA_PRIVILEGED_CLASS` |
| `API-08` | API | L2 | api | gate_rule | `DOMAIN_NO_CAA`、`ZT_DENY_BY_DEFAULT` |
| `API-09` | API | L2 | api | gate_rule | `API_OPERATION_DUPLICATE`、`SSOT_UNREGISTERED` |
| `API-10` | API | L2 | api | gate_rule | `API_SIGNATURE`、`TOPO_FAIL_OPEN` |
| `ASVS-1.4.1` | ASVS | L2 | backend | gate_rule | `AUTHZ_DEFAULT_DECISION`、`AUTHZ_ROLE_PERMISSION_UNKNOWN` |
| `ASVS-1.4.4` | ASVS | L2 | backend | test | `tools/tests/test_b19_authz.py::AuthzDecisionFunction::test_the_maker_cannot_be_the_checker` |
| `ASVS-10.3.2` | ASVS | L2 | supply_chain | gate_rule | `CI_REQUIRED_STAGE`、`TOOLCHAIN_DIGEST` |
| `ASVS-12.1.1` | ASVS | L2 | api | accepted_gap | — |
| `ASVS-13.2.1` | ASVS | L2 | api | gate_rule | `API_ERROR_STATUS`、`API_PATH` |
| `ASVS-14.4.1` | ASVS | L2 | api | test | `tools/tests/test_b22_baseline.py::HardeningReference::test_missing_security_headers_are_reported` |
| `ASVS-14.5.2` | ASVS | L2 | api | test | `tools/tests/test_b22_baseline.py::HardeningReference::test_wildcard_cors_with_credentials_is_rejected` |
| `ASVS-2.2.1` | ASVS | L2 | backend | gate_rule | `MFA_PUSH_FATIGUE`、`MFA_RATE_LIMIT` |
| `ASVS-2.5.4` | ASVS | L2 | backend | gate_rule | `ID_RECOVERY_DOWNGRADE`、`MFA_RECOVERY_BYPASS` |
| `ASVS-2.8.1` | ASVS | L2 | backend | gate_rule | `AUTHZ_ROLE_NO_MFA`、`MFA_WEAK_FOR_PRIVILEGED` |
| `ASVS-3.3.1` | ASVS | L2 | backend | gate_rule | `ID_REVOCATION_CHECK`、`ZT_SESSION` |
| `ASVS-3.5.3` | ASVS | L2 | backend | gate_rule | `ID_BEARER_TOKEN`、`ID_BINDING_METHOD` |
| `ASVS-4.1.3` | ASVS | L2 | backend | gate_rule | `AUTHZ_STANDING_ELEVATED`、`AUTHZ_STANDING_PRIVILEGE` |
| `ASVS-4.2.2` | ASVS | L2 | api | gate_rule | `API_MUTATION_NOT_IDEMPOTENT`、`ID_CSRF` |
| `ASVS-5.1.3` | ASVS | L2 | api | test | `tools/tests/test_b22_baseline.py::HardeningReference::test_amount_parsing_rejects_floats_and_junk` |
| `ASVS-5.3.4` | ASVS | L2 | backend | accepted_gap | — |
| `ASVS-6.2.1` | ASVS | L2 | backend | accepted_gap | — |
| `ASVS-6.4.1` | ASVS | L2 | backend | gate_rule | `CONFIG_LITERAL_SECRET`、`KEY_APP_HOLDS_MATERIAL`、`KEY_HARDCODED` |
| `ASVS-6.4.2` | ASVS | L2 | backend | gate_rule | `CERT_NO_OVERLAP`、`KEY_NO_SHREDDING`、`KEY_ROTATION_MISSING` |
| `ASVS-7.1.1` | ASVS | L2 | backend | gate_rule | `API_ERROR_LEAK`、`KEY_IN_LOGS` |
| `ASVS-7.1.2` | ASVS | L2 | backend | test | `tools/tests/test_b22_baseline.py::HardeningReference::test_redaction_strips_card_numbers_and_credentials` |
| `ASVS-8.3.4` | ASVS | L2 | backend | gate_rule | `AUTHZ_FIELD_CLASSIFICATION`、`KEY_FIELD_UNPROTECTED` |
| `ASVS-9.1.1` | ASVS | L2 | backend | gate_rule | `CERT_SELF_SIGNED_EDGE`、`ZT_BOUNDARY_REQUIREMENTS` |
| `MASVS-AUTH-2` | MASVS | L2 | mobile | accepted_gap | — |
| `MASVS-CRYPTO-1` | MASVS | L2 | mobile | accepted_gap | — |
| `MASVS-NETWORK-1` | MASVS | L2 | mobile | accepted_gap | — |
| `MASVS-STORAGE-1` | MASVS | L2 | mobile | accepted_gap | — |

- **`API-01` 失效的对象级授权（BOLA）**：对象归属在租户判定之后仍要单独判定。
- **`API-02` 失效的身份认证**：禁止 alg=none 与隐式流。
- **`API-03` 对象属性级授权失效（BOPLA）**：字段级白名单 + 卡号任何人不可读。
- **`API-04` 资源消耗无限制**：限流策略在 B18/B19 有声明，但没有实现层；属于 B4x。
- **`API-05` 功能级授权失效**：权限必须显式授予且特权角色有额外要求。
- **`API-08` 安全配置错误**：默认拒绝 + CAA 限制签发方。
- **`API-09` 库存管理不当（未知/影子接口）**：接口与治理文件都必须登记在册。
- **`API-10` 不安全地消费第三方 API**：渠道回调必须验签，依赖不得 fail open。
- **`ASVS-1.4.1` 访问控制在可信服务层强制执行，不依赖客户端**：默认拒绝 + 权限必须显式授予，由 B19 的授权模型强制。
- **`ASVS-1.4.4` 同一套访问控制机制贯穿全应用**：唯一的判定函数，四层判定顺序固定。
- **`ASVS-10.3.2` 部署物完整性可验证**：CI 有必需阶段，工具链依赖按摘要固定（不是浮动版本）。
- **`ASVS-12.1.1` 限制上传大小/资源消耗**：没有实现层，属于 B4x API 实现批次。
- **`ASVS-13.2.1` API 使用与操作语义一致的方法与状态码**：由 B11 的 API 契约强制。
- **`ASVS-14.4.1` 响应带安全响应头**：HSTS、CSP、nosniff、frame-ancestors 缺一即报。
- **`ASVS-14.5.2` CORS 不使用通配符配合凭据**：`Access-Control-Allow-Origin: *` 与 `Allow-Credentials: true` 同时出现是明确错误。
- **`ASVS-2.2.1` 对认证器实施抗自动化攻击控制**：限流与防推送疲劳由 B18 强制。
- **`ASVS-2.5.4` 账号恢复不得降低认证强度**：恢复路径是账号接管最常用的入口。
- **`ASVS-2.8.1` 高权限操作使用抗钓鱼认证器**：特权角色清单由 B19 统一，MFA 要求由 B18 强制。
- **`ASVS-3.3.1` 会话在登出与超时后失效**：每次请求检查撤销，人类会话有上限。
- **`ASVS-3.5.3` 使用不透明或已签名的会话令牌，且绑定持有者**：不存在无绑定的 bearer 令牌。
- **`ASVS-4.1.3` 最小权限原则**：不存在常驻特权，高危权限只能限时提权获得。
- **`ASVS-4.2.2` 状态改变操作有反自动化/反 CSRF 控制**：state/nonce 必需；写操作必须幂等。
- **`ASVS-5.1.3` 所有输入在服务端校验**：金额解析拒绝浮点、指数、空白与超限值。
- **`ASVS-5.3.4` 输出编码/参数化查询防止注入**：本仓目前没有查询层实现，参数化查询属于实现批次。
- **`ASVS-6.2.1` 使用经过审计的密码学实现，不自行实现算法**：参考实现刻意使用非真实密码学（B20 §8 已声明），真实实现必须替换为经审计的 AEAD 库。
- **`ASVS-6.4.1` 密钥由密钥管理方案保管，不硬编码**：禁止硬编码密钥材料，应用不持有密钥。
- **`ASVS-6.4.2` 密钥有轮换与销毁流程**：轮换有重叠期，销毁是密码学销毁。
- **`ASVS-7.1.1` 日志不含凭证与支付敏感数据**：另有运行期脱敏函数（见 ASVS-7.1.2）。
- **`ASVS-7.1.2` 日志与错误信息脱敏**：把一段真实的异常堆栈交给脱敏函数，卡号与密钥都不应出现在输出里。
- **`ASVS-8.3.4` 敏感数据在存储中加密**：B19 分类为敏感的字段必须有数据密钥保护。
- **`ASVS-9.1.1` 通信使用 TLS，且内部通信也加密**：内部区域间的访问要求包含 mutual TLS（B16 的 zone_rules），边缘禁止自签证书。
- **`MASVS-AUTH-2` 移动端本地认证不可被绕过**：本平台没有自有移动应用；本地生物识别绕过属于 App 侧风险，届时必须重新评估（见复核批次）。
- **`MASVS-CRYPTO-1` 移动端使用平台密码学 API**：本平台没有自有移动应用，因此没有可供审计的移动端密码学调用；一旦有 App，本条必须重新评估。
- **`MASVS-NETWORK-1` 移动端强制 TLS 并校验证书**：同样因为没有自有移动应用；证书固定与 TLS 强制属于 App 侧，届时需连同发布流程一起评估。
- **`MASVS-STORAGE-1` 移动端不在本地存储敏感数据**：本平台没有自有移动应用；商户与付款人使用浏览器或渠道自身的 App，本地存储不在我们的控制面内。

## 明确记录的缺口

| 要求 | 负责人 | 复核批次 | 理由 |
| --- | --- | --- | --- |
| `API-04` | platform-security | B40 | 限流策略在 B18/B19 有声明，但没有实现层；属于 B4x。 |
| `ASVS-12.1.1` | platform-security | B40 | 没有实现层，属于 B4x API 实现批次。 |
| `ASVS-5.3.4` | platform-security | B40 | 本仓目前没有查询层实现，参数化查询属于实现批次。 |
| `ASVS-6.2.1` | platform-security | B40 | 参考实现刻意使用非真实密码学（B20 §8 已声明），真实实现必须替换为经审计的 AEAD 库。 |
| `MASVS-AUTH-2` | platform-security | B60 | 本平台没有自有移动应用；本地生物识别绕过属于 App 侧风险，届时必须重新评估（见复核批次）。 |
| `MASVS-CRYPTO-1` | platform-security | B60 | 本平台没有自有移动应用，因此没有可供审计的移动端密码学调用；一旦有 App，本条必须重新评估。 |
| `MASVS-NETWORK-1` | platform-security | B60 | 同样因为没有自有移动应用；证书固定与 TLS 强制属于 App 侧，届时需连同发布流程一起评估。 |
| `MASVS-STORAGE-1` | platform-security | B60 | 本平台没有自有移动应用；商户与付款人使用浏览器或渠道自身的 App，本地存储不在我们的控制面内。 |
