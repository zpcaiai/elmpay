# B30 plan — 商户接入与四眼审批

Batch: 商户接入与四眼审批 · Wave W03 · Skill `pay-onboarding-tenant-isolation` · depends_on: [B28]

## 1. 范围

批次目标里有一个词决定了整个批次：**可恢复**。
一个不能从中断处继续的工作流，最终都是靠人手工做完的：
六步里第四步在凌晨失败，从头再来意味着重新导凭证、重新验域名，
于是有人「直接去库里把状态改成已上线」。那一刻，上面所有审批记录都失去意义。
所以本批次**不提供任何手工完成路径**——一个存在的手工出口，一定会被用掉。

1. `governance/onboarding-workflow.json`：6 个步骤、四眼审批、恢复规则、
   域名验证、回调验证、凭证、限额、停用。
2. `tools/paygov/onboarding.py`：接入门禁（57 条规则码），含三条跨批次校验——
   审批权限必须在 B19 是双人控制、限额默认值引用的风险等级必须在 B25 存在、
   **B26 必须仍要求回调往返才能激活绑定**（本工作流的上线步骤就是那次跃迁）。
3. `libs/onboarding/reference/workflow.py`：**可执行、可恢复的工作流**
   （幂等步骤、副作用计数、摘要绑定的审批；`force_complete()` 永远抛异常）。
4. `tools/paygov/onboardinggen.py` + `scripts/render-onboarding.py`。
5. `scripts/onboarding-smoke.py`：38 项运行期断言。
6. `tools/tests/test_b30_onboarding.py`：107 个用例。
7. `tools/negative/b30.py`：29 个负向控制场景。

## 2. 受影响组件

`governance/{onboarding-workflow,ssot-registry}.json`、
`tools/paygov/{onboarding,onboardinggen}.py`、`libs/onboarding/`、
`scripts/{render-onboarding,onboarding-smoke}.py`、
`contracts/onboarding/workflow.json`、`docs/onboarding/ONBOARDING_WORKFLOW.md`、
`tools/tests/test_b30_onboarding.py`、`tools/negative/b30.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **`execute()` 幂等**：已完成的步骤返回 `ALREADY_DONE` 且**不再产生副作用**；
  `side_effect_count()` 让这条性质可被断言，而不是靠代码阅读。
- **`force_complete()` 永远抛异常**。它存在只是为了让「没有手工路径」这件事可被测试。
- **`approve()` 绑定摘要**，摘要覆盖 `payout_account` 与 `limits`。
  `amend()` 改到摘要内字段就地作废批准；即使有人绕过 `amend()` 直接改 payload，
  `go_live()` 仍会因摘要不符而拒绝（`APPROVAL_STALE`）。这是双保险，因为
  「先批准、再改收款账户、然后上线」正是这条流程最经典的绕过方式。
- **回调地址拒绝内网地址**。一个指向 `169.254.169.254` 的「回调地址」
  是让平台替人访问自己元数据服务的请求。
- **停用一人、恢复两人**。与 B28 的「上线双人、回滚零人」同源：
  两个方向的风险不对称，流程也就不该对称。

## 4. 错误语义

`ONB_UNREADABLE`、`ONB_SHAPE`、`ONB_VERSION_FIELD`、`ONB_PRINCIPLE`、`ONB_NO_STEPS`、
`ONB_STEP_ID`、`ONB_STEP_DUPLICATE`、`ONB_STEP_NO_ORDER`、`ONB_STEP_ORDER_COLLISION`、
`ONB_STEP_EFFECT_UNSTATED`、`ONB_STEP_NOT_IDEMPOTENT`、`ONB_STEP_NOT_RESUMABLE`、
`ONB_STEP_NO_EVIDENCE`、`ONB_STEP_NOTES`、`ONB_STEP_MISSING`、`ONB_APPROVAL_AFTER_GO_LIVE`、
`ONB_LIMITS_AFTER_GO_LIVE`、`ONB_APPROVAL_UNBOUND`、`ONB_SINGLE_EYE`、`ONB_SELF_APPROVAL`、
`ONB_DIGEST_INCOMPLETE`、`ONB_APPROVAL_NEVER_EXPIRES`、`ONB_APPROVAL_SURVIVES_CHANGE`、
`ONB_PERMISSION_UNKNOWN`、`ONB_APPROVAL_NOTES`、`ONB_NOT_RESUMABLE`、
`ONB_REPLAYS_SIDE_EFFECTS`、`ONB_MANUAL_COMPLETION`、`ONB_RESUME_UNBOUNDED`、
`ONB_RESUMPTION_NOTES`、`ONB_DOMAIN_METHOD`、`ONB_DOMAIN_TOKEN_REUSABLE`、
`ONB_DOMAIN_TOKEN_ETERNAL`、`ONB_DOMAIN_WILDCARD`、`ONB_DOMAIN_NOTES`、
`ONB_CALLBACK_UNPROVEN`、`ONB_CALLBACK_UNSIGNED`、`ONB_CALLBACK_PLAINTEXT`、
`ONB_CALLBACK_SSRF`、`ONB_CALLBACK_NOTES`、`ONB_CREDENTIAL_ECHO`、`ONB_CREDENTIAL_REIMPORT`、
`ONB_CREDENTIAL_SIDE_PATH`、`ONB_CREDENTIAL_NOTES`、`ONB_NO_LIMITS_AT_GO_LIVE`、
`ONB_LIMIT_RAISE_UNGATED`、`ONB_RISK_LEVELS_UNKNOWN`、`ONB_LIMIT_NOTES`、
`ONB_SUSPEND_NEEDS_APPROVAL`、`ONB_SUSPEND_DELAYED`、`ONB_REINSTATE_SINGLE_PERSON`、
`ONB_SUSPENSION_NOTES`、`ONB_AUDIT_CLASS_UNKNOWN`、`ONB_GO_LIVE_UNPROVEN`、
`ONB_GENERATED_MISSING`、`ONB_GENERATED_DRIFT`、`ONB_GENERATED`。

运行期拒绝码：`UNKNOWN_STEP`、`OUT_OF_ORDER`、`ALREADY_LIVE`、`NOT_APPROVED`、
`APPROVAL_EXPIRED`、`APPROVAL_STALE`、`SELF_APPROVAL`、`NOT_ENOUGH_EYES`、`NO_EVIDENCE`、
`CASE_EXPIRED`、`CREDENTIAL_NOT_READABLE`、`DOMAIN_TOKEN_USED`、`DOMAIN_TOKEN_EXPIRED`、
`DOMAIN_WILDCARD`、`CALLBACK_NOT_HTTPS`、`CALLBACK_PRIVATE_ADDRESS`、`NO_LIMITS`、
`NOT_SUSPENDED`、`MANUAL_COMPLETION`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify onboarding-workflow --repo .
python3 scripts/render-onboarding.py --check
python3 scripts/onboarding-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 导凭证 → 验域名 → 验回调 → 设限额 → 四眼审批 → 上线 |
| **恢复** | 中断后 `resume()` 指向下一个未完成步骤；重复执行返回 `ALREADY_DONE`；**副作用计数不增加**；乱序被拒；未知步骤被拒；无证据被拒 |
| **无手工路径** | `force_complete()` 永远抛 `MANUAL_COMPLETION` |
| 过期 | 半途而废的接入超过 `max_resume_days` 后不能再恢复 |
| 凭证 | 重复导入返回同一引用；**永远不能读回** |
| 域名 | 通配符被拒；令牌重用被拒；令牌过期被拒 |
| 回调 | 非 HTTPS 被拒；`169.254.169.254`/`127.0.0.1`/`10.x`/`192.168.x`/`localhost` 五种内网地址全部被拒；验签失败被拒 |
| **审批** | 申请人不能批准自己；一人不够；同一人重复计数不够；批准绑定摘要；批准会过期；改收款账户即作废；**绕过 `amend()` 直接改 payload 也会在上线时被摘要发现**；改无关字段不影响批准 |
| 上线 | 步骤不全被拒；未批准被拒；无限额被拒；成功后重复上线被拒 |
| 停用 | 一人立即停用；恢复一人不够、两人可以；未停用时不能恢复 |
| 拒绝 | 57 条规则各有用例：手工完成路径、重放副作用、步骤不幂等、审批不绑定内容、摘要缺收款账户、审批不过期、单人审批、审批在上线之后、限额在上线之后、凭证可回显、通配符域名、内网回调、停用需审批、恢复单人…… |
| 跨批次 | B19 撤掉 `config.write` 双人 → `ONB_SINGLE_EYE`；B25 清空风险等级 → `ONB_RISK_LEVELS_UNKNOWN`；B26 取消回调往返要求 → `ONB_GO_LIVE_UNPROVEN` |
| 失败关闭 | 模型坏到无法生成契约时 `ONB_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `onboarding-smoke.py` 38 项断言；负向控制新增 29 个 B30 场景，共 398 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-onboarding.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **门禁指出了 `go_live` 的拒绝码不够具体**。第一版在缺审批时返回 `OUT_OF_ORDER`，
  而运维需要知道的是「缺审批 / 审批过期 / 审批失效」这三者中的哪一个。已改成先查审批。
- **没有存储、没有并发、没有锁**。`Case` 是进程内对象；
  「状态落盘」在治理模型里是一个 `true`，本批次**不提供实现**。
  真实工作流需要乐观锁——两个运维同时点「上线」在这里不会出错，在真实系统里会。
- **域名验证不查 DNS**。`verify_domain()` 只做令牌一次性、有效期与通配符检查；
  真正的 TXT 查询、CNAME 跟随、DNS 缓存与投毒防护都属于实现批次。
- **内网地址检查是前缀匹配**。真实的 SSRF 防护要解析 DNS 后再检查目标 IP、
  处理重定向、处理 DNS rebinding、覆盖 IPv6 与十进制/八进制表示法——
  **本批次的实现挡不住这些**，它只是把「必须检查」这件事写进契约。
- **审批只有「几个人」没有「哪些角色」**。真实的四眼要求风控 + 财务而不是任意两人；
  角色约束属于 B19 的权限模型，本批次没有把它接过来。
- **限额只是一个字典**。它与 B25 风险等级的联动、与 B29 费率的关系、
  以及「调高限额」这条子流程都只是声明，没有实现。
- **`amend()` 与直接改 payload 的双保险说明了一件事**：
  只要对象是可变的，就没有真正的绑定。真实系统里 payload 应该是不可变快照 + 版本号，
  本批次用「上线时重算摘要」兜住，但**这不是同等强度的保证**。

## 9. 数据迁移

无。真实落地时需要把现有的人工接入记录导入为已完成的历史 case，属于实现批次。

## 10. 证据与审查

`evidence/B30/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B29 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **接入流程中断** | 手工改状态完成 → 上面所有审批失去意义 | 步骤幂等 + 从断点恢复 + **没有手工完成路径** |
| 恢复时重跑已完成步骤 | 重复导入凭证、重复发上线事件 | `ALREADY_DONE` 且副作用计数不变 |
| **先批准再改收款账户** | 审计记录读起来是一次合规的接入，钱却去了别处 | 审批绑定内容摘要 + 变更即作废 + 上线时二次校验 |
| 半年前的批准 | 批准的是另一个世界 | 批准 72 小时过期 |
| 商户填一个内网回调地址 | 平台替人访问自己的元数据服务 | 回调地址拒绝内网前缀、必须 HTTPS、必须往返验签 |
| 「让我确认一下密钥填对了没有」 | 一个能读出全部渠道密钥的接口 | 凭证永不回显 |
| 事故中要停用商户 | 停用需要审批 → 多等一个人醒来 | 停用一人、立即生效；恢复才需要两人 |
