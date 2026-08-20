# B18 plan — 抗钓鱼 MFA 与 WebAuthn

Batch: 抗钓鱼 MFA 与 WebAuthn · Wave W02 · Skill `pay-phishing-resistant-access` · depends_on: [B16]

## 1. 范围

B17 说「身份是什么、怎么被偷」。B18 只回答一个问题：
**当用户本人被骗到一个假站点上、并且完全配合攻击者时，认证还能不能守住。**

答案只有一种形式：认证器的响应必须绑定**它自己看到的 origin**。
用户能念出来、能转发、能点「同意」的任何东西，在这个威胁模型下都等于没有。

1. `governance/mfa.json`：5 个认证器（2 个抗钓鱼、3 个不抗钓鱼）、4 类角色要求、
   WebAuthn 参数、step-up 规则、回退策略、注册策略、限流策略。
2. `tools/paygov/mfa.py`：MFA 门禁（39 条规则码），含跨事实源检查——
   B16 声明需要 `phishing_resistant_mfa` 因素时，必须真有认证器提供它；
   B17 的特权账号恢复路径不得成为 MFA 的绕过口。
3. `libs/mfa/reference/webauthn.py`：**可执行的 WebAuthn 断言校验器**（含判定顺序）。
4. `tools/paygov/mfagen.py` + `scripts/render-mfa.py`，生成
   `contracts/security/mfa-matrix.json` 与 `docs/security/MFA.md`。
5. `scripts/mfa-smoke.py`：钓鱼、重放、克隆、未绑定 step-up 等场景，21 项运行期断言。
6. `tools/tests/test_b18_mfa.py`：80 个用例。

## 2. 受影响组件

`governance/{mfa,ssot-registry}.json`、`tools/paygov/{mfa,mfagen,registry}.py`、
`libs/mfa/`、`scripts/{render-mfa,mfa-smoke}.py`、
`contracts/security/mfa-matrix.json`、`docs/security/MFA.md`、
`tools/tests/test_b18_mfa.py`、`scripts/negative-controls.py`（扩至 144 个场景）。

## 3. 领域接口与数据契约

- **抗钓鱼不是形容词，是一个可判定的性质**：认证器的响应是否绑定 origin。
  `kind ∈ {otp, push}` 的认证器**一律不得**声明 `phishing_resistant: true`——
  这不是保守，是定义：能被人念出来或转发的东西，中间人就能实时转发。
  规则 `MFA_MISCLASSIFIED` 就是为了防止有人靠改一个布尔值把 SMS 变成「抗钓鱼」。
- **特权角色只接受抗钓鱼认证器**。`platform-operator`、`break-glass`、`merchant-admin`
  三类角色的 `allowed_authenticators` 里出现任何一个 `phishing_resistant: false` 的认证器，
  门禁直接拒（`MFA_WEAK_FOR_PRIVILEGED`）。`break-glass` 更严：只接受外置安全密钥，
  因为平台内置认证器与设备同生共死，而紧急通道恰恰要在设备被攻陷时仍然可信。
- **没有回退降级**。`fallback.downgrade_allowed` 必须为 `false`。
  「密钥不在手边就用短信」这句话的真实含义是：这个账号的安全级别就是短信。
- **step-up 必须绑定这一次操作**。只证明「刚才有人验证过」的 step-up，
  在会话被劫持后毫无价值——攻击者复用的正是那次验证。`transaction_binding` 必须为 `true`。
- **挑战一次性 + 限时**（32 字节、120 秒、`challenge_single_use`），
  否则断言可重放；**签名计数器回退视为认证器被克隆**并拒绝。
- **付款人不强制 MFA**。这是一个明确的取舍而不是遗漏：强制会把大量正常支付挡在门外，
  而付款人不持有平台权限，其风险由风控与限额承担。写进模型是为了让这个决定**可被审查**。

## 4. 错误语义

`MFA_UNREADABLE`、`MFA_VERSION_FIELD`、`MFA_SHAPE`、`MFA_PRINCIPLE`、`MFA_RP_ID`、`MFA_ORIGIN`、
`MFA_ORIGIN_BINDING`、`MFA_USER_VERIFICATION`、`MFA_CHALLENGE`、`MFA_CHALLENGE_REPLAY`、
`MFA_SIGN_COUNT`、`MFA_ATTESTATION`、`MFA_ALGORITHM`、`MFA_STEP_UP`、`MFA_NO_TRANSACTION_BINDING`、
`MFA_DOWNGRADE_FALLBACK`、`MFA_ENROLMENT`、`MFA_SINGLE_AUTHENTICATOR`、`MFA_RATE_LIMIT`、
`MFA_PUSH_FATIGUE`、`MFA_AUTH_ID`、`MFA_AUTH_DUPLICATE`、`MFA_AUTH_KIND`、
`MFA_AUTH_CLASSIFICATION`、`MFA_AUTH_NOTES`、`MFA_MISCLASSIFIED`、`MFA_SOLE_FACTOR`、
`MFA_RESISTANT_CLASS`、`MFA_ROLE`、`MFA_ROLE_NOTES`、`MFA_ROLE_UNCOVERED`、
`MFA_PRIVILEGED_CLASS`、`MFA_WEAK_FOR_PRIVILEGED`、`MFA_UNKNOWN_AUTHENTICATOR`、
`MFA_FACTOR_UNBACKED`、`MFA_RECOVERY_BYPASS`、`MFA_GENERATED_MISSING`、`MFA_GENERATED_DRIFT`、
`MFA_GENERATED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify mfa --repo .
python3 scripts/render-mfa.py --check
python3 scripts/mfa-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 合法断言通过：origin、RP ID、挑战、user verification、签名、计数器递增全部满足 |
| **钓鱼** | **假站点拿到用户的全部配合仍然失败**：断言里的 origin 是钓鱼站，校验器**第一步**就拒 |
| 判定顺序 | origin 先于一切被检查——先验签再看 origin 的实现会在错误的地方泄露信息，顺序本身是被测的 |
| 重放 | 同一个挑战用第二次被拒；过期挑战被拒；未签发的挑战被拒 |
| 克隆 | 签名计数器回退被拒（`CLONED_AUTHENTICATOR`） |
| step-up | 绑定操作摘要的断言通过；摘要不匹配的断言被拒——这条区分了「有人验证过」和「他批准了这一笔」 |
| 拒绝 | 39 条规则各有用例：SMS 改标为抗钓鱼、推送提升为单因素、运营降级到 TOTP、紧急通道只留一把钥匙、step-up 去掉绑定、允许回退降级、挑战可重用、计数器回退不再判克隆、user verification 降到 discouraged、接受 http origin、删掉 merchant-admin 要求…… |
| 跨批次 | B16 要求的 `phishing_resistant_mfa` 无认证器支撑时 `MFA_FACTOR_UNBACKED`；B17 特权恢复接受更弱因素时 `MFA_RECOVERY_BYPASS` |
| 失败关闭 | 模型坏到无法生成契约时给出 `MFA_GENERATED` 而非崩溃；`--budget-seconds 0` 退出码 3 |
| 运行期 | `mfa-smoke.py` 21 项断言；负向控制新增 14 个 B18 场景，共 144 个场景 |
| 删除击杀 | 16 个新规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-mfa.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **没有真实密码学，也没有 CBOR/COSE 解析**。`libs/mfa/reference/webauthn.py` 里
  `signature_valid` 是断言对象上的一个布尔字段，`clientDataJSON` 与 `authenticatorData`
  是已经解析好的结构体。本批次证明的是**判定顺序与拒绝条件**，
  **不是**「我们的 WebAuthn 实现是正确的」。真实实现需要 COSE 公钥解析、
  ES256/RS256 验签、`authData` 位标志与 RP ID hash 比对。
- **证明链（attestation）完全没有验证**。模型要求 `attestation: direct`，
  但没有任何代码校验 AAGUID、根证书链或 FIDO MDS 状态。
  也就是说，本批次**无法**保证「注册的确实是一把合规的安全密钥」。属于有网络与构建环境的批次。
- **注册与限流只有策略没有实现**。「至少两个认证器」「10 次/小时」「900 秒锁定」
  「防推送疲劳」都是**要求**，谁来执行、状态存在哪里、跨节点怎么共享计数，
  属于 B19（SoD/JIT）与后续的运营批次。
- **`MFA_ROLE_UNCOVERED` 只检查硬编码的 `PRIVILEGED_ROLES` 三个角色**。
  新增一类高权限角色但忘了写 MFA 要求时，这条规则抓不到——
  与 B16 §8 的 `ZT_HIGH_RISK`、B17 §8 的 `ID_RECOVERY_UNCOVERED` 是**同一类缺口**：
  特权角色清单没有单一事实源。建议在 B19 建立角色清单后一并回补三处。
- **降级回退在模型里是一个布尔值**。真实系统里的降级往往不写在配置里，
  而是藏在客服流程、账号申诉与「临时开通」里。本批次挡不住那种降级。
- **推送批准被定义为「不是因素」，但没有验证它是否仍被当作因素使用**。
  模型里 `allowed_as_sole_factor: false` 只约束模型自身。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B18/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B16 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 用户会被骗到像素级相同的假站点，并全力配合 | 任何用户能转述的凭据（OTP、短信码）都会被实时转发（AC-04） | 特权角色只接受 origin 绑定的认证器；`kind ∈ {otp,push}` 一律不得声明抗钓鱼 |
| 「密钥忘带了」是一个每天都会发生的真实场景 | 回退路径成为账号的真实安全级别（AC-05） | `downgrade_allowed: false`；特权账号必须注册 ≥2 个认证器，让「丢一个」不再需要回退 |
| 会话在验证之后仍可能被劫持 | 复用一次成功的 step-up 批准另一笔资金操作 | step-up 必须绑定操作摘要；摘要不匹配即拒（运行期断言覆盖） |
| 断言可以被录下来 | 重放同一个断言 | 挑战一次性、120 秒过期、32 字节随机 |
| 认证器可能被物理克隆 | 两个「同一把钥匙」并存 | 签名计数器回退判定为克隆并拒绝 |
| 推送批准可以连发到用户点同意 | 推送疲劳攻破（AC-04） | 推送在本平台不是因素；另有限流与推送疲劳保护 |
| **恢复流程是绕过 MFA 最省事的路径** | 特权账号恢复接受更弱因素即等于没有 MFA | 跨读 B17 恢复路径：禁止仅短信、必须同等或更强因素（`MFA_RECOVERY_BYPASS`） |
| 零信任策略可以声明一个不存在的因素 | 「我们要求抗钓鱼 MFA」是一句没有实现支撑的话 | 跨读 B16 因素清单，无认证器支撑即 `MFA_FACTOR_UNBACKED` |
