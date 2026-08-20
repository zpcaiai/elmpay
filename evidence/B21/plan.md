# B21 plan — 密钥、证书与域名生命周期

Batch: 密钥、证书与域名生命周期 · Wave W02 · Skill `pay-cryptography-key-lifecycle` · depends_on: [B20]

## 1. 范围

B20 管的是密钥的**结构**（谁包谁、怎么加密）。B21 管的是密钥与证书的**时间**：
它们几乎从不是被破解的，而是**到期**、**换不动**、**撤销没生效**。

1. `governance/certificates.json`：8 份材料、3 个域名、告警策略、恢复策略、禁止项。
2. `tools/paygov/certs.py`：生命周期门禁（44 条规则码），含与 B20（密钥托管）
   和 B17（JWKS 轮换周期）的跨批次校验。
3. `libs/pki/reference/lifecycle.py`：**可执行的生命周期引擎**（重叠期、撤销、升级、恢复）。
4. `tools/paygov/certsgen.py` + `scripts/render-certs.py`，生成
   `contracts/security/certificate-inventory.json` 与 `docs/security/CERTIFICATE_LIFECYCLE.md`。
5. `scripts/certs-smoke.py`：轮换、重叠、撤销、CAA、恢复共 23 项运行期断言。
6. `tools/tests/test_b21_certs.py`：84 个用例。
7. `tools/negative/b21.py`：15 个负向控制场景（放在本批次自己的模块里，见 §3 末）。

## 2. 受影响组件

`governance/{certificates,ssot-registry}.json`、`tools/paygov/{certs,certsgen}.py`、
`libs/pki/`、`scripts/{render-certs,certs-smoke}.py`、
`contracts/security/certificate-inventory.json`、`docs/security/CERTIFICATE_LIFECYCLE.md`、
`tools/tests/test_b21_certs.py`、`tools/negative/b21.py`。

**注意：本批次没有修改任何既有批次的产物**，因此不需要全量重新基线——
这是上一次程序卫生改造（校验器与负向控制场景改为发现制）之后的第一个批次，
也是那次改造是否真的生效的验证。

## 3. 领域接口与数据契约

- **重叠期是本批次的核心**。轮换当天，旧材料必须**仍然可验证**：
  在途令牌、渠道方缓存的 JWKS、还没重启的 Pod，不会在同一瞬间切换。
  没有重叠期的轮换 = 需要停机的轮换 = 永远不会执行的轮换，最后变成「到期自己挂掉」。
- **撤销压倒重叠期**。「它还在窗口期内」正是被盗证书最想要的理由，
  所以 `revoke` 在参考实现里直接使版本失效，与重叠期无关。
- **提前量是绝对值与比例的下限组合**：`min(有效期/3, 60 天)`。
  纯比例会要求五年期的 CA 证书提前 20 个月告警——那不是谨慎，那是**不可满足的规则**，
  而不可满足的规则会被关掉。（这条是门禁在本批次开发过程中自己发现的：
  最初的纯比例规则一次性判了 6 份材料不合格，其中 4 份其实是规则错了。）
- **短寿命材料必须自动续期**：7 天有效期 + 人工续期 = 每周赌一次有没有人记得。
  反过来，人工续期的材料提前量不得少于 30 天，因为人的流程不是脚本。
- **连续两次自动续期失败必须升级人工**。证书到期最常见的剧本不是「没人管」，
  而是「机器人一直在重试，没人知道它一直失败」。
- **域名是 TLS 的地基**：注册商锁 + DNSSEC + CAA。域名被劫持时，
  攻击者能签出一张**真正合法**的证书，此时 TLS 什么都证明不了。
  内部域名的 CAA 只允许自建 CA——公共 CA 不应该能为它签发。
- **CT 日志监控**：任何为我们域名签出的、不是我们申请的证书，都是最早的入侵信号。
- **恢复必须被演练过**。一条从未走过的恢复流程，在事故当天不可信；
  参考实现里 `recover()` 对未演练的策略直接抛异常。
- **本批次的负向控制场景写在 `tools/negative/b21.py`**，不再追加到 `scripts/negative-controls.py`。
  后者是 B00 的产物，过去每个批次都要改它，于是每个批次都要把前面所有批次的证据重签一遍。

## 4. 错误语义

`CERT_UNREADABLE`、`CERT_SHAPE`、`CERT_VERSION_FIELD`、`CERT_PRINCIPLE`、`CERT_STAGES`、
`CERT_ID`、`CERT_DUPLICATE`、`CERT_KIND`、`CERT_OWNER`、`CERT_NOTES`、`CERT_NO_REVOCATION`、
`CERT_NO_VALIDITY`、`CERT_RENEW_MARGIN`、`CERT_NO_OVERLAP`、`CERT_OVERLAP_TOO_LONG`、
`CERT_MANUAL_SHORT_LIVED`、`CERT_MANUAL_MARGIN`、`CERT_ALERT_CHANNELS`、
`CERT_ALERT_THRESHOLD`、`CERT_NO_ESCALATION`、`CERT_NO_ISSUER_ALERT`、
`CERT_NO_CT_MONITORING`、`CERT_UNREHEARSED_RECOVERY`、`CERT_REHEARSAL_INTERVAL`、
`CERT_RECOVERY_TIME`、`CERT_NO_CA_BACKUP`、`CERT_RECOVERY_QUORUM`、`CERT_SELF_SIGNED_EDGE`、
`CERT_SHARED_ENVIRONMENT_KEY`、`CERT_KEY_UNMANAGED`、`CERT_ROTATION_SLOWER_THAN_IDENTITY`、
`CERT_PROVIDER_UNTRACKED`、`CERT_GENERATED_MISSING`、`CERT_GENERATED_DRIFT`、`CERT_GENERATED`、
`DOMAIN_NAME`、`DOMAIN_DUPLICATE`、`DOMAIN_NO_LOCK`、`DOMAIN_NO_DNSSEC`、`DOMAIN_NO_CAA`、
`DOMAIN_NO_RENEWAL`、`DOMAIN_RENEW_MARGIN`、`DOMAIN_OWNER`、`DOMAIN_NOTES`。

运行期状态与拒绝码：`OK`、`RENEW_DUE`、`EXPIRED`、`REVOKED`、`UNKNOWN`、
`UNAUTHORISED_ISSUER`、`QUORUM_NOT_MET`、`UNREHEARSED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify certificates --repo .
python3 scripts/render-certs.py --check
python3 scripts/certs-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 新签发 → 进入提前量 → 到期，三态转换齐全；刚签发时到期清单为空 |
| **重叠** | 轮换当天 `accepting == [旧, 新]`；重叠期内旧版本仍验签；重叠期结束旧版本被拒；新版本一直可用 |
| 边界 | 重叠期不会把旧材料拖过它**自己的**到期日；未来版本在签发前不被接受；连续两次轮换不会复活更老的版本 |
| **撤销** | 撤销在重叠期内立即生效；只影响那一个版本；撤销不存在的版本被拒 |
| 告警 | 连续失败达到阈值升级人工；成功后计数归零；到期清单列出需要处理的材料 |
| 域名 | CAA 之外的签发方被拒、之内的被接受；未知域名被拒；域名到期同样有三态 |
| 恢复 | 法定人数不足被拒；未演练的恢复路径被拒 |
| 拒绝 | 44 条规则各有用例：提前量缩到 2 天、去掉重叠期、七天证书改人工、去掉撤销途径、失败不升级、关掉 CT 监控、去掉注册商锁/DNSSEC/CAA、恢复不演练、恢复不要法定人数、材料指向未托管密钥…… |
| 跨批次 | 材料指向 B20 未管理的密钥 → `CERT_KEY_UNMANAGED`；HSM 托管的渠道密钥没有到期日 → `CERT_PROVIDER_UNTRACKED`；签名密钥寿命超过 B17 的 JWKS 轮换周期 → `CERT_ROTATION_SLOWER_THAN_IDENTITY`；`key-management.json` 损坏时门禁**给出发现而不是崩溃** |
| 失败关闭 | 模型坏到无法生成契约时 `CERT_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `certs-smoke.py` 23 项断言；负向控制新增 15 个 B21 场景，共 198 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-certs.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **没有 X.509、没有 ACME、没有 DNS**。`libs/pki/reference/lifecycle.py` 里
  「证书」是一个有签发日与到期日的记录，没有解析、没有链校验、没有 OCSP 请求。
  本批次证明的是**生命周期的状态机**，不是「我们的证书处理是正确的」。
- **时间是入参的整数天**。没有时区、没有闰秒、没有「证书的 notAfter 是 UTC 而告警脚本用本地时区」
  这类真实世界里**真正会造成事故**的问题。
- **撤销只在本模型内立即生效**。真实的 CRL/OCSP 有缓存与传播延迟，
  「撤销了」和「所有验证方都知道它被撤销了」之间的窗口没有建模——
  这也是为什么 `internal-mtls` 用 7 天短寿命而不是依赖撤销。
- **轮换没有分发环节**。新材料如何送到每个节点、送不到时怎么办（这才是重叠期真正要覆盖的风险），
  属于 B101 及运维批次。
- **CT 日志监控只有要求没有实现**：谁去拉日志、多久一次、误报怎么处理，都不在本批次。
- **`CERT_PROVIDER_UNTRACKED` 用的是子串匹配**（`apple_pay` → `apple-pay-processing`）。
  命名一旦不规则，这条规则会漏掉——**这是已知缺口**，
  正确做法是让 B20 的 `provider_keys` 直接引用本批次的材料 id，建议在有实现批次时统一。
- **域名到期是模型里的一个天数**，没有与注册商对账；真实的域名到期只有注册商知道。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B21/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B20 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **证书会到期，而且总在周末** | 全站不可用，且修复需要人、需要审批、需要签发方配合 | 提前量 = `min(有效期/3, 60 天)`；多通道告警；连续失败升级人工 |
| 轮换要停机，所以没人轮换 | 密钥用到过期为止，泄露后也换不动 | 重叠期让新旧同时有效；运行期证明轮换当天两个版本都验签 |
| 被盗证书仍在有效期内 | 「还在窗口期」成为放行理由 | 撤销立即生效且压倒重叠期；短寿命 mTLS 使撤销延迟不再重要 |
| **域名被劫持** | 攻击者拿到一张真正合法的证书，TLS 不再证明任何事 | 注册商锁 + DNSSEC + CAA；内部域名不信任公共 CA |
| CA 误签或被骗签 | 我们不知道有一张我们的证书存在 | CT 日志监控 + 非预期签发方告警 |
| 自动续期静默失败 | 机器人一直重试，没人知道 | 连续 2 次失败升级人工，成功后计数归零 |
| CA 材料丢失 | 无法签发任何新证书，且无法恢复 | 离线备份 + 法定人数 + 4 小时恢复目标 + **每半年演练一次** |
| 生产与测试共用密钥 | 泄露的是测试环境，受影响的是生产 | `shared_key_across_environments` 必须为 false |
