# B20 plan — KMS、HSM 与信封加密

Batch: KMS、HSM 与信封加密 · Wave W02 · Skill `pay-cryptography-key-lifecycle` · depends_on: [B18]

## 1. 范围

B19 决定谁能读一个字段。B20 决定**当有人绕过所有这些判断、直接拿走数据库或备份时，他拿到的是什么**。

密钥在这里不是配置项，是能力：应用进程从不「拥有」根密钥或 KEK，
它只是在 300 秒内借到一次解密能力，而且每次借用都留痕。

1. `governance/key-management.json`：三层密钥（root/KEK/DEK）、信封参数、HSM 要求、
   9 个提供方密钥、轮换与紧急轮换、密码学销毁、禁用算法。
2. `tools/paygov/keys.py`：密钥门禁（57 条规则码），含两条跨批次校验——
   B17 的每个身份提供方与项目配置里的每个渠道都必须有托管密钥；
   B19 标记为敏感的每个字段都必须有数据密钥保护。
3. `libs/kms/reference/envelope.py`：**可执行的信封加密参考实现**（含认证包裹与 AAD 绑定）。
4. `tools/paygov/keysgen.py` + `scripts/render-keys.py`，生成
   `contracts/security/key-inventory.json` 与 `docs/security/KEY_MANAGEMENT.md`。
5. `scripts/kms-smoke.py`：把密文搬到另一个租户、改一个比特、重用 nonce、
   过期租期、轮换、销毁——24 项运行期断言。
6. `tools/tests/test_b20_keys.py`：102 个用例。

## 2. 受影响组件

`governance/{key-management,ssot-registry}.json`、`tools/paygov/{keys,keysgen,registry}.py`、
`libs/kms/`、`scripts/{render-keys,kms-smoke}.py`、
`contracts/security/key-inventory.json`、`docs/security/KEY_MANAGEMENT.md`、
`tools/tests/test_b20_keys.py`、`scripts/negative-controls.py`（扩至 182 个场景）。

## 3. 领域接口与数据契约

- **三层密钥**：根密钥只在 HSM 内、不可导出、2/3 法定人数；KEK 按用途与租户切分；
  数据密钥一条记录一把，随密文以**被包裹**的形式同存。
- **AAD 绑定租户、用途与密钥版本**。这是整批最重要的一行配置：
  没有它，一条密文被复制到另一个租户的行上会**干净地解开**。
  参考实现里 `decrypt` 用的是**调用方给的**租户与用途，不是信封自己声称的——
  如果信任信封自己的声明，这个防护就等于不存在。
- **包裹也是认证的**。每租户一把 KEK 时，搬家的密文连数据密钥都解不开（`WRAP_INVALID`）；
  共享 KEK 时才轮到 AAD 挡（`AUTH_FAILED`）。两道机制**独立**，这是刻意的。
- **拒绝时不解释是「被改了」还是「搬家了」**。AEAD 本来就分不出这两者，
  编一个更具体的理由既是在编造信息，也是在给攻击者反馈。
- **nonce 重用被显式禁止**。GCM 下重用 nonce 不是「减弱」，是机密性与完整性同时归零。
- **明文数据密钥有租期**（300 秒），过期后 `DataKeyLease.material()` 直接抛异常而不是继续可用。
- **轮换只重新包裹数据密钥**，不重写业务数据；7 天重叠期内旧版本仍可解密，之后停用；
  泄露时 4 小时内必须完成紧急轮换。
- **密码学销毁**：租户下线销毁其 KEK，备份里的密文从此不可解——
  在一个有备份的系统里，这是唯一**能被验证**的删除。
- **卡号与 CVV 不在这里加密**，因为它们根本不被存储（B19/NN-04）。
  为它们建密钥反而是在承认我们留着它们，因此 `KEY_NEVER_STORED_ENCRYPTED` 会拒绝这种写法。

## 4. 错误语义

`KEY_UNREADABLE`、`KEY_SHAPE`、`KEY_VERSION_FIELD`、`KEY_PRINCIPLE`、`KEY_HSM_REQUIRED`、
`KEY_HSM_LEVEL`、`KEY_HSM_ATTESTATION`、`KEY_EXPORTABLE_ROOT`、`KEY_QUORUM`、`KEY_ALGORITHM`、
`KEY_DEK_SCOPE`、`KEY_NONCE_SIZE`、`KEY_NONCE_REUSE`、`KEY_AAD_MISSING`、`KEY_PLAINTEXT_TTL`、
`KEY_UNWRAPPED_STORED`、`KEY_ID`、`KEY_DUPLICATE`、`KEY_CLASS`、`KEY_STORAGE`、`KEY_EXPORTABLE`、
`KEY_NOTES`、`KEY_ROTATION_MISSING`、`KEY_ROOT_STORAGE`、`KEY_ROOT_DUAL_CONTROL`、
`KEY_ROOT_DIRECT_USE`、`KEY_DEK_STORAGE`、`KEY_DEK_UNWRAPPED`、`KEY_WRAPPER_UNKNOWN`、
`KEY_WRAPPER_CLASS`、`KEY_ROTATION_INVERTED`、`KEY_NO_KEK`、`KEY_ROTATION_PERIOD`、
`KEY_ROTATION_OVERLAP`、`KEY_REENCRYPT_STRATEGY`、`KEY_EMERGENCY_ROTATION`、
`KEY_APP_HOLDS_MATERIAL`、`KEY_BROKER_BYPASS`、`KEY_USE_UNAUDITED`、`KEY_AUDIT_VERSION`、
`KEY_NO_SHREDDING`、`KEY_SHRED_RECOVERABLE`、`KEY_WEAK_ALGORITHM_ALLOWED`、`KEY_WEAK_ALGORITHM`、
`KEY_RSA_SIZE`、`KEY_HARDCODED`、`KEY_IN_LOGS`、`KEY_PROVIDER_DUPLICATE`、
`KEY_PROVIDER_MATERIAL`、`KEY_PROVIDER_KEY_UNKNOWN`、`KEY_PROVIDER_NOTES`、
`KEY_PROVIDER_UNMANAGED`、`KEY_FIELD_UNPROTECTED`、`KEY_NEVER_STORED_ENCRYPTED`、
`KEY_GENERATED_MISSING`、`KEY_GENERATED_DRIFT`、`KEY_GENERATED`。

运行期拒绝码另成一套：`AUTH_FAILED`、`WRAP_INVALID`、`NONCE_REUSE`、`LEASE_EXPIRED`、
`KEY_DESTROYED`、`KEY_VERSION_RETIRED`、`UNKNOWN_KEY`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify key-management --repo .
python3 scripts/render-keys.py --check
python3 scripts/kms-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 加解密往返一致；密文不含明文；每条记录的包裹密钥都不同 |
| **搬家** | 每租户 KEK 时 `WRAP_INVALID`；共享 KEK 时 `AUTH_FAILED`——**两道机制分别被单独证明** |
| 完整性 | 改一个比特、伪造标签都被拒；拒绝码不透露是哪种攻击 |
| nonce | 同密钥版本下重用被拒；换 nonce 正常；nonce 过短被拒 |
| 租期 | 租期内可用、到点抛异常；解密调用同样受租期约束 |
| 轮换 | 新版本产生 → 重叠期内旧版本仍可解 → 重新包裹不动密文 → 重叠期后旧版本停用 |
| 销毁 | 销毁前可解、销毁后永久不可解、且只影响那一个租户 |
| 审计 | 加密、解密、**被拒绝的解密**都留痕，且带密钥版本 |
| 拒绝 | 57 条规则各有用例：根密钥可导出、法定人数变 1、AAD 去掉、去掉租户绑定、允许 nonce 重用、明文数据密钥存一天、存未包裹的数据密钥、KEK 十年轮换一次、去掉重叠期、解禁 MD5、渠道私钥无人托管、敏感字段无密钥…… |
| 跨批次 | 新增一个敏感字段但没有密钥 → `KEY_FIELD_UNPROTECTED`；把承诺不存储的卡号列为加密字段 → `KEY_NEVER_STORED_ENCRYPTED`；`identity.json` 损坏时门禁**给出发现而不是崩溃** |
| 失败关闭 | 模型坏到无法生成契约时给出 `KEY_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `kms-smoke.py` 24 项断言；负向控制新增 17 个 B20 场景，共 182 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-keys.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **这不是真正的密码学，而且必须被这样理解**。`libs/kms/reference/envelope.py`
  的机密性原语是 SHA-256 keystream，不是 AES-GCM；认证部分用的是**真实的 HMAC-SHA-256**，
  因为本批次要证明的性质（密文不能搬家、篡改会被发现）本来就是认证性质，
  用假的 MAC 去「证明」它等于什么都没证明。真实实现必须使用经过审计的 AEAD 库。
- **没有真实 KMS/HSM**。密钥材料由 SHA-256 从种子派生，`KeyBroker` 是进程内对象。
  真实的 KMS 有网络、有配额、有可用区故障、有 IAM——这些都没有建模。
- **没有 PKCS#11 / 云 KMS 的 API 语义**：批量解密、密钥策略、Grant、跨区域复制、
  以及 HSM 不可用时的降级行为（**这恰恰是最容易被写成「先明文跑着」的地方**）都属实现批次。
- **轮换是手动调用**。没有调度器、没有「到期未轮换」的告警，
  `rotation_days` 只是一个被门禁检查的数字，没有任何东西保证它真的发生。
- **密码学销毁只覆盖 KEK 层**。真实系统里还有缓存、只读副本、以及**离线备份磁带**，
  「销毁密钥」要在这些地方也成立才算数；本批次不覆盖。
- **`KEY_FIELD_UNPROTECTED` 依赖 B19 的字段分类**。没有被分类的字段（例如某天有人加了
  `passport_number` 却忘了写 `field_rules`）不会被任何规则发现——
  这是与 B19 §8 第 5 条同源的缺口：**清单本身的完整性没有被守护**。
- **提供方密钥只检查算法与托管方式**，不检查密钥实际存在、也不检查它与渠道配置一致。

## 9. 数据迁移

无。真实落地时需要一次「明文 → 信封」的回填迁移，属于实现批次。

## 10. 证据与审查

`evidence/B20/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B18 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **数据库或备份整体外泄** | 有权限的读取路径全部绕过，直接拿走数据（AC-08） | 敏感字段一律信封加密；数据密钥一条一把；密钥不在数据库里 |
| 攻击者能写入行，但拿不到密钥 | 把 A 租户的加密银行账号复制到 B 租户的行上，让 B 帮自己解开 | AAD 绑定租户/用途/版本 + 每租户 KEK 的认证包裹，**两道独立机制**，各有运行期证明 |
| 密文可以被逐字节修改 | 改掉金额、改掉账号 | 认证加密：一个比特的改动即被拒 |
| 实现者图省事复用 nonce | GCM 下同密钥两条密文可互相抵消出明文并可伪造 | 模型显式禁止 + 参考实现在加密时就拒绝 |
| 应用进程被攻陷 | 内存里若有长期密钥，等于密钥被拿走 | 应用不持有密钥材料；明文数据密钥 300 秒租期，过期即不可用 |
| 密钥泄露后需要更换 | 「重加密全部数据」的方案没人敢执行，于是永远不换 | 轮换只重新包裹数据密钥；7 天重叠期；紧急轮换 4 小时 |
| 租户要求「删除我的数据」 | 有备份的系统里，删行不等于删数据 | 销毁租户 KEK 即密码学销毁，且**只影响该租户**（运行期证明） |
| 单人动用根密钥 | 最高权限的一次静默使用 | HSM 内不可导出 + 2/3 法定人数 + 双人复核 + 每次使用留痕（含版本） |
