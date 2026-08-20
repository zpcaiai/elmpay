# B17 plan — 客户、管理员与服务身份

Batch: 客户、管理员与服务身份 · Wave W02 · Skill `pay-zero-trust-identity` · depends_on: [B16]

## 1. 范围

B16 说「每次访问都要有已认证身份」。B17 回答：**身份到底是什么，以及它怎么被偷走。**

1. `governance/identity.json`：4 个发行方、7 种令牌、3 条账号恢复路径、
   OAuth/OIDC 流程约束、撤销机制、令牌绑定、服务账号规则、
   与 B16 全部 7 类主体的身份绑定。
2. `tools/paygov/identity.py`：身份门禁（47 条规则），含跨事实源检查：
   B16 的每一个主体都必须有身份绑定；人的令牌不得长于零信任会话上限。
3. `libs/identity/reference/tokens.py`：**可执行的令牌校验器**（含判定顺序）。
4. `tools/paygov/idgen.py` + `scripts/render-identity.py`，生成
   `contracts/security/identity.json` 与 `docs/security/IDENTITY.md`。
5. `scripts/identity-smoke.py`：对全部 7 种令牌做 8 类攻击，19 项运行期断言。
6. `tools/tests/test_b17_identity.py`：87 个用例。

## 2. 受影响组件

`governance/{identity,ssot-registry}.json`、`tools/paygov/{identity,idgen,registry}.py`、
`libs/identity/`、`scripts/{render-identity,identity-smoke}.py`、
`contracts/security/identity.json`、`docs/security/IDENTITY.md`、
`tools/tests/{test_b17_identity.py,support.py}`、`scripts/negative-controls.py`（扩至 130 个场景）。

## 3. 领域接口与数据契约

- **没有无绑定的 bearer 令牌**。所有令牌绑定到持有者密钥（DPoP 或 mTLS）。
  理由很实际：日志、代理、浏览器扩展、崩溃上报**每天都在复制令牌**；
  绑定之后，复制到的那份没有私钥，就是废纸。
- **禁止 `alg: none` 与对称算法**。校验器**先检查算法再检查签名**——
  经典绕过就是让令牌自己决定怎么被校验。对称密钥意味着任何能**验证**的一方也能**伪造**。
- **只允许授权码流 + PKCE(S256)**，重定向 URI **精确匹配**（前缀匹配就是开放重定向，NN-10），
  state 与 nonce 都必需。隐式流把令牌放进 URL，密码流让每个客户端摸到用户密码。
- **令牌有受众**。一个在受众之外仍被接受的令牌，就是所有服务的令牌。
- **撤销每次请求都检查**，60 秒内全局生效（与 B16 一致）。只能等过期的撤销不是撤销。
- **服务账号不存在静态密钥**，凭据一律由工作负载身份签发（NN-07）。
- **账号恢复**是账号接管最常用的入口，因为它就是为「持有者什么都丢了」设计的：
  - 恢复不得比原因素更弱（否则更弱的那个才是账号的真实安全级别）；
  - **禁止仅短信恢复**——SIM 交换会让最高权限账号一夜易主；
  - 高权限账号恢复需 24 小时冷静期 + 多渠道通知，给真正的持有者喊停的机会。

## 4. 错误语义

`ID_UNREADABLE`、`ID_VERSION_FIELD`、`ID_SHAPE`、`ID_PRINCIPLE`、`ID_BEARER_TOKEN`、
`ID_FORBIDDEN_ALGORITHM`、`ID_FLOW`、`ID_FORBIDDEN_FLOW`、`ID_PKCE`、`ID_REDIRECT_MATCH`、
`ID_CSRF`、`ID_REVOCATION_DEADLINE`、`ID_REVOCATION_CHECK`、`ID_BINDING_REQUIRED`、
`ID_BINDING_METHOD`、`ID_STATIC_SERVICE_ACCOUNT`、`ID_PROVIDER_ID`、`ID_PROVIDER_DUPLICATE`、
`ID_PROVIDER_NOTES`、`ID_ISSUER`、`ID_AUDIENCE`、`ID_ALGORITHM`、`ID_KEY_ROTATION`、
`ID_TOKEN_LIFETIME`、`ID_CLOCK_SKEW`、`ID_TOKEN_ID`、`ID_TOKEN_DUPLICATE`、`ID_TOKEN_KIND`、
`ID_TOKEN_PROVIDER`、`ID_TOKEN_REVOCABLE`、`ID_TOKEN_NOTES`、`ID_RECOVERY_SUBJECT`、
`ID_RECOVERY_METHOD`、`ID_RECOVERY_DOWNGRADE`、`ID_RECOVERY_SMS`、`ID_RECOVERY_NOTIFY`、
`ID_RECOVERY_DELAY`、`ID_RECOVERY_NOTES`、`ID_RECOVERY_UNCOVERED`、`ID_PRINCIPAL_UNBACKED`、
`ID_PRINCIPAL_PROVIDER`、`ID_PRINCIPAL_TOKEN`、`ID_PRINCIPAL_UNKNOWN`、
`ID_LIFETIME_EXCEEDS_SESSION`、`ID_GENERATED_MISSING`、`ID_GENERATED_DRIFT`、`ID_GENERATED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify identity --repo .
python3 scripts/render-identity.py --check
python3 scripts/identity-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 7 种令牌的 happy path 全部通过校验；每种令牌的受众都属于它的发行方 |
| **偷窃** | **7/7 令牌在换持有者密钥后被拒**（`WRONG_HOLDER`）——这一条就是令牌绑定存在的理由 |
| 算法 | `alg=none` 与 `HS256` 全部被拒，且**在签名校验之前**被拒（判定顺序本身是被测的） |
| 受众 | 校验器只配置自己的受众；跨受众令牌全部被拒 |
| 过期 | 超出时钟容差即拒；容差内仍接受；容差 ≤300 秒；未来签发被拒 |
| 撤销 | 撤销后**下一次**校验立即被拒 |
| 拒绝 | 47 条规则各有用例：允许 bearer、放行对称算法、开回隐式流、PKCE 降级为 plain、重定向前缀匹配、只在登录时查撤销、运营恢复降级为短信、去掉冷静期、允许静态服务账号密钥、主体没有身份绑定…… |
| 失败关闭 | 模型坏到无法生成契约时给出 `ID_GENERATED` 而非崩溃 |
| 运行期 | `identity-smoke.py` 19 项断言；负向控制新增 11 个 B17 场景，共 130 个场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-identity.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **没有真实密码学**。`libs/identity/reference/tokens.py` 里 `signature_valid` 是一个布尔字段，
  不是验签结果。本批次验证的是**判定顺序与拒绝条件**，
  **不是**「我们的签名校验实现是正确的」。真实的 JWKS 拉取、缓存、轮换与验签
  需要密码学库与网络，属于有构建环境的批次。
- **DPoP 证明没有建模**。绑定检查在模型里是「presented_key == token.holder_key」的字符串比较。
  真实的 DPoP 要校验证明 JWT 的签名、`htm`/`htu`/`jti` 与重放窗口。
  换句话说：本批次证明的是**绑定这件事有意义**，不是「我们的 DPoP 实现是对的」。
- **抗钓鱼 MFA 只是一个名字**。`phishing_resistant_mfa` 在 B16 里是因素名，
  在这里是恢复路径的一个约束，**它的真实强度由 B18（WebAuthn）负责**。
  本批次没有验证过任何一次 MFA。
- **恢复流程只有策略没有实现**。24 小时冷静期、多渠道通知、线下核验都是**要求**，
  谁来执行、怎么防止内部人绕过，属于 B19（SoD）与 B101（后台运维）。
- **JWKS 轮换只检查了天数上限**，没有建模轮换期间新旧密钥并存的窗口，
  也没有建模密钥泄露后的紧急轮换（属于 B20/B21）。
- **`ID_RECOVERY_UNCOVERED` 只检查 `platform-operator` 一个主体**。
  如果新增了一类高权限账号但忘了写恢复路径，这条规则抓不到。
  更完整的做法是与 B16 的主体清单交叉——**这是已知缺口**，建议在 B19 一并补上
  （与 B16 §8 记的 `ZT_HIGH_RISK` 缺口是同一类问题）。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B17/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B16 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 令牌会被复制到日志、代理与崩溃上报 | 任何拿到副本的人都获得该身份 | 全部令牌绑定持有者密钥；**7/7 令牌换密钥即被拒**的运行期证明 |
| 攻击者可以选择令牌的算法 | `alg: none` 或对称密钥伪造（经典 JWT 绕过） | 算法**先于**签名校验；`none` 与 `HS*` 在契约层与校验器层各拒一次 |
| 重定向 URI 常被写成前缀匹配 | 开放重定向 → 授权码被劫持（NN-10、FF-09） | `redirect_uri_matching` 必须为 `exact`，负向控制场景覆盖 |
| 令牌在受众之外被接受 | 一个前端令牌能直接调内部 API | 每个令牌声明受众；校验器只配置自己的受众；跨受众全部被拒 |
| 撤销常被实现成「等它过期」 | 事故中无法立刻切断访问 | 每次请求检查撤销 + 60 秒全局生效；撤销后下一次校验立即被拒 |
| 服务账号密码长期存在 | 三年前泄露今天依然有效（NN-07） | 禁止静态密钥，凭据一律工作负载身份签发 |
| **账号恢复是为「什么都丢了」设计的** | 这正是攻击者的处境；恢复弱于主因素时，弱的那个才是真实安全级别（AC-05） | 恢复不得降级 + 禁止仅短信（SIM 交换）+ 高权限 24 小时冷静期 + 多渠道通知 |
