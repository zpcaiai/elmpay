# B19 plan — RBAC、ABAC、职责分离与限时提权

Batch: RBAC、ABAC、职责分离与临时授权 · Wave W02 · Skill `pay-phishing-resistant-access` · depends_on: [B18]

## 1. 范围

B16 说每次访问都要被授权，B17 说请求者是谁，B18 说这个「是谁」有多可信。
B19 回答剩下的那半句：**这个人到底能做什么，能动哪一行，能看哪一个字段。**

四层判定，每一层的默认答案都是拒绝：权限是否被授予（RBAC）→ 请求是否留在自己的租户内（ABAC）
→ 对象是否属于这个租户 → 字段是否可读。资金动作再加一层：**提出的人不能是批准的人。**

1. `governance/authorization.json`：9 个角色、15 项权限、5 条字段规则、5 条职责分离约束、
   双人复核参数、限时提权（JIT）策略、审计要求。
2. `tools/paygov/authz.py`：授权门禁（约 55 条规则码），含**特权角色单一事实源**的跨批次校验。
3. `libs/authz/reference/decision.py`：**可执行的授权判定函数**（判定顺序即规范）。
4. `tools/paygov/authzgen.py` + `scripts/render-authz.py`，生成
   `contracts/security/authorization-matrix.json` 与 `docs/security/AUTHORIZATION.md`。
5. `scripts/authz-smoke.py`：一个人试图独自完成一笔资金动作的 22 项运行期断言。
6. `tools/tests/test_b19_authz.py`：107 个用例。

## 2. 受影响组件

`governance/{authorization,ssot-registry}.json`、`tools/paygov/{authz,authzgen,registry}.py`、
`libs/authz/`、`scripts/{render-authz,authz-smoke}.py`、
`contracts/security/authorization-matrix.json`、`docs/security/AUTHORIZATION.md`、
`tools/tests/test_b19_authz.py`、`scripts/negative-controls.py`（扩至 162 个场景）。
**并回改** `governance/mfa.json`（新增 2 条角色要求）与 `governance/identity.json`
（新增 3 条恢复路径）——原因见 §3 末与 §11。

## 3. 领域接口与数据契约

- **默认拒绝**。`default_decision` 必须是 `deny`；允许即默认的模型不是授权模型。
- **四层判定，顺序固定**（`libs/authz/reference/decision.py` 从上往下读就是规范）：
  权限 → 租户 → 对象 → 字段。判定函数**在说「不」之前不会返回任何数据**。
- **资金动作必须双人**，且审批要满足四件事：不是自己批的、批的人本身有这个权限、
  没有过期、**绑定这一次请求的摘要**。最后一条与 B18 的 step-up 交易绑定是同一个道理：
  不绑定的审批只证明「有人批过某件事」，可以被搬到另一笔出款上。
- **职责分离是两层的**：模型层禁止同一角色同时持有互斥权限（`AUTHZ_SOD_VIOLATION`），
  实例层禁止「谁创建、谁批准」（`DENY_SEPARATION_OF_DUTIES`）。
  只做模型层，同一个人换两个账号仍然能走完全程；只做实例层，权限设计本身就是错的。
  `SOD-02`（改收款账户 + 批准出款）是这里最危险的一对：**它不改金额，只改钱的去向**。
- **字段级不是权限问题**。卡号与 CVV 对任何角色都不可读，没有例外、没有提权、没有审批
  能让它们可读（NN-04）。个人信息默认脱敏，`readable_by` 是白名单而不是黑名单。
- **不存在常驻特权**。`ledger.adjust`、`cross_tenant_data.read`、`config.write`
  只能通过提权获得：有审批人（不是自己）、有票据、≤60 分钟、到点自动收回。
  紧急通道更短（30 分钟）且**每次使用 24 小时内必须有人复核**。
- **审计记录允许与拒绝**，并带上规则版本——事后要能回答「当时为什么放行」。
- **特权角色清单在这里是唯一事实源**。B16、B17、B18 各自硬编码了一份特权角色名单，
  三个批次都把这件事写成了已知缺口。本批次把它收敛成一个字段（`privileged`），
  并让门禁去核对：一个角色被标记为特权，它就**必须**在 `governance/mfa.json` 里有
  抗钓鱼 MFA 要求、在 `governance/identity.json` 里有恢复路径、
  在 `governance/zero-trust.json` 里有对应主体。

## 4. 错误语义

`AUTHZ_UNREADABLE`、`AUTHZ_SHAPE`、`AUTHZ_VERSION_FIELD`、`AUTHZ_PRINCIPLE`、
`AUTHZ_DEFAULT_DECISION`、`AUTHZ_PERMISSION_ID`、`AUTHZ_PERMISSION_DUPLICATE`、
`AUTHZ_PERMISSION_SCOPE`、`AUTHZ_PERMISSION_SENSITIVITY`、`AUTHZ_PERMISSION_NOTES`、
`AUTHZ_PERMISSION_UNUSED`、`AUTHZ_MONEY_NO_DUAL_CONTROL`、`AUTHZ_ROLE_ID`、
`AUTHZ_ROLE_DUPLICATE`、`AUTHZ_ROLE_KIND`、`AUTHZ_ROLE_SCOPE`、`AUTHZ_ROLE_NOTES`、
`AUTHZ_ROLE_PRIVILEGED_FLAG`、`AUTHZ_ROLE_PERMISSION_UNKNOWN`、`AUTHZ_FIELD_NAME`、
`AUTHZ_FIELD_DUPLICATE`、`AUTHZ_FIELD_CLASSIFICATION`、`AUTHZ_FIELD_NOTES`、
`AUTHZ_FIELD_READER_UNKNOWN`、`AUTHZ_FIELD_PAN_READABLE`、`AUTHZ_FIELD_MASK`、
`AUTHZ_FIELD_UNGOVERNED`、`AUTHZ_SOD_ID`、`AUTHZ_SOD_DUPLICATE`、`AUTHZ_SOD_NOTES`、
`AUTHZ_SOD_UNKNOWN_PERMISSION`、`AUTHZ_SOD_VIOLATION`、`AUTHZ_SOD_MISSING`、
`AUTHZ_DUAL_APPROVALS`、`AUTHZ_DUAL_SELF_APPROVAL`、`AUTHZ_DUAL_TTL`、`AUTHZ_DUAL_BINDING`、
`AUTHZ_STANDING_PRIVILEGE`、`AUTHZ_STANDING_ELEVATED`、`AUTHZ_ELEVATION_DURATION`、
`AUTHZ_ELEVATION_APPROVAL`、`AUTHZ_ELEVATION_TICKET`、`AUTHZ_ELEVATION_AUTO_REVOKE`、
`AUTHZ_ELEVATION_UNKNOWN_PERMISSION`、`AUTHZ_ELEVATION_UNKNOWN_ROLE`、
`AUTHZ_AUDITOR_ELEVATABLE`、`AUTHZ_BREAK_GLASS_DURATION`、`AUTHZ_BREAK_GLASS_REVIEW`、
`AUTHZ_BREAK_GLASS_NOTIFY`、`AUTHZ_AUDIT_DECISIONS`、`AUTHZ_AUDIT_DENIALS`、
`AUTHZ_AUDIT_RULE_VERSION`、`AUTHZ_AUDIT_IMMUTABLE`、`AUTHZ_NO_PRIVILEGED_ROLE`、
`AUTHZ_ROLE_NO_MFA`、`AUTHZ_ROLE_NO_RECOVERY`、`AUTHZ_ROLE_NO_ZT_PRINCIPAL`、
`AUTHZ_GENERATED_MISSING`、`AUTHZ_GENERATED_DRIFT`、`AUTHZ_GENERATED`。

判定函数的拒绝原因是另一套常量（`DENY_*`），刻意与门禁规则码分开：
一个是「模型写错了」，一个是「这次请求不被允许」。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify authz --repo .
python3 scripts/render-authz.py --check
python3 scripts/authz-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 财务批准由管理员发起的退款：审批人不同、权限具备、未过期、绑定摘要 |
| **独自完成** | 自己批自己（`DENY_SELF_APPROVAL`）、发起人执行复核（`DENY_SEPARATION_OF_DUTIES`）、无审批（`DENY_MISSING_APPROVAL`）全部被拒 |
| **审批重放** | 审批真实、人对、未过期，但绑定的是**另一笔**的摘要 → 被拒 |
| 租户/对象 | 跨租户读被拒；租户对了但对象属于别人时仍被拒 |
| 字段 | 卡号对任何角色都不可读（整个请求被拒，而不是「返回但打码」）；默认脱敏；白名单角色可见全文 |
| 提权 | 未提权被拒 → 提权后放行且审计带票据 → 到点失效 → 撤销后立即失效；非法申请在**签发环节**就被拒（超时限、自批、无票据、不可提权的权限、不可提权的角色） |
| 紧急通道 | 时限比常规提权更短，超时限的申请被拒 |
| 拒绝 | 约 55 条规则各有用例：允许即默认、资金动作去掉双人、审批不绑定、审批永不过期、删掉一条职责分离、常驻特权、提权只发不收、审计员可提权、卡号变可读…… |
| 跨批次 | 特权角色缺 MFA 要求 / 缺恢复路径 / 缺零信任主体，三条各有用例；`governance/mfa.json` 损坏时门禁**给出发现而不是崩溃** |
| 失败关闭 | 模型坏到无法生成契约时给出 `AUTHZ_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `authz-smoke.py` 22 项断言；负向控制新增 18 个 B19 场景，共 162 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-authz.py`、`render-mfa.py`、
`render-identity.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **判定函数不是运行中的服务**。它是一个纯函数，没有策略分发、没有缓存失效、
  没有与数据库行级安全（B13 的 RLS）的联动。真实系统里「对象属于哪个租户」由 SQL 判定，
  这里由入参判定——**本批次证明的是判定顺序与拒绝条件，不是端到端隔离**。
- **审批与提权没有存储**。`Approval` 与 `Elevation` 是入参对象；谁签发、存在哪、
  跨节点如何一致、撤销如何在 60 秒内全局生效（B16 的要求），都属于实现批次。
- **摘要绑定只是字符串比较**。真实实现要对请求做规范化序列化再哈希并签名，
  否则「同一笔」的定义本身就可以被绕过。
- **字段脱敏只返回字段名**，没有真的做脱敏；`masked_fields` 是一份「这些字段必须打码」的清单，
  真正打码发生在序列化层，本批次没有覆盖。
- **`AUTHZ_PERMISSION_UNUSED` 会掩盖一个反向问题**：它只保证权限有人能持有，
  不保证权限**被正确的人**持有。「谁应该有这个权限」仍然是人的判断，门禁替不了。
- **职责分离只覆盖显式声明的 5 对**。没有声明的组合（例如未来新增的权限）不会被自动发现；
  `AUTHZ_SOD_MISSING` 只强制资金类双人权限至少出现在一条规则里，这是下限不是上限。
- **紧急通道的事后复核只有要求没有实现**：谁复核、复核没做怎么办，属于 B101 运营批次。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B19/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B18 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 一个被攻陷的账号想独自走完资金流程 | 发起 + 批准同一个人（AC-06） | 模型层禁止同角色持有互斥权限；实例层禁止发起人复核；两层都有运行期证明 |
| 审批可以被搬到另一笔上 | 一个合法审批变成可复用的通行证 | 审批绑定请求摘要 + 900 秒过期 + 审批人必须本身有该权限 |
| **改收款账户不改金额** | 最安静的偷钱方式：钱照付，只是付给别人（`SOD-02`） | 改账户与批出款必须两个人；两者都是双人复核动作 |
| 运营账号长期持有高危权限 | 攻陷发生在哪一小时都无所谓（AC-07） | 不存在常驻特权；提权有审批、票据、≤60 分钟、自动收回 |
| 紧急通道被当成日常后门 | 「先用紧急账号顶一下」变成常态 | 紧急通道 30 分钟上限 + 24 小时内必须复核 + 多渠道通知 |
| 客服席位是社会工程学入口 | 一次电话骗到完整卡号或银行账号 | 卡号任何人不可读；银行账号对客服默认脱敏；字段白名单 |
| 审计员被授予「临时修复权限」 | 审计者能改自己审计的对象 | `auditor` 在 `non_elevatable_roles` 中，签发环节就拒 |
| **特权角色清单各批次自己维护** | 新增一类高权限角色时，MFA、恢复、零信任三处都可能忘记（B16/B17/B18 各记过一次） | 清单收敛为一个字段，门禁跨读三个文件核对——**本批次因此发现了 `break-glass` 根本没有恢复路径** |
