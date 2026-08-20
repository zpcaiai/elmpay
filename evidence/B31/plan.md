# B31 plan — 租户隔离验证

Batch: 租户隔离验证 · Wave W03 · Skill `pay-onboarding-tenant-isolation` · depends_on: [B30, B29]

## 1. 范围

本批次的关键词是**验证**，不是隔离。隔离在 B13/B24 里已经声明过了；
这里要回答的是「凭什么相信它」。答案是：**每个隔离面都必须有一个断言「另一个租户被拒」的探针**。
只断言「本租户看得到」的测试对隔离一无所知——把过滤器整个删掉，它照样全绿。
本批次的运行期证明里就演示了这一点：对表属主不强制行级安全时，
正向断言依然通过，而此时租户 A 已经能读到租户 B 的行。

1. `governance/tenant-isolation.json`：8 个隔离面及其探针、强制控制、
   缓存、消息、日志、导出、证据政策。
2. `tools/paygov/isolation.py`：隔离门禁（48 条规则码），含五条跨批次校验——
   B13 的每张租户表必须启用行级安全**且对属主强制**、B13 必须声明会话变量、
   B24 必须仍禁止跨租户引用、跨租户权限必须在 B19 是双人控制、
   审计类别必须是 B23 的 `data.access`。
3. `libs/isolation/reference/probes.py`：**可执行的隔离探针**
   （数据库、对象存储、缓存、消息、日志、导出、搜索、后台任务）。
4. `tools/paygov/isolationgen.py` + `scripts/render-isolation.py`。
5. `scripts/isolation-smoke.py`：31 项运行期断言。
6. `tools/tests/test_b31_isolation.py`：96 个用例。
7. `tools/negative/b31.py`：27 个负向控制场景。

## 2. 受影响组件

`governance/{tenant-isolation,ssot-registry}.json`、`tools/paygov/{isolation,isolationgen}.py`、
`libs/isolation/`、`scripts/{render-isolation,isolation-smoke}.py`、
`contracts/tenancy/isolation.json`、`docs/tenancy/TENANT_ISOLATION.md`、
`tools/tests/test_b31_isolation.py`、`tools/negative/b31.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **探针必须断言拒绝**。`run_probes()` 逐个执行每个隔离面声明的探针；
  探针不存在 → `PROBE_MISSING`；探针没能拒绝 → `PROBE_DID_NOT_DENY`。
  这两个拒绝码让「有探针」这件事本身可被验证，而不是靠 JSON 里一个 `true`。
- **`Database` 把行级安全建模成存储的性质而不是调用方的性质**：
  没有租户上下文的 `select()` **抛异常**，不是返回全部；
  `force_for_owner=False` 时属主看到全部——那正是反例演示用的配置。
- **缓存、消息、日志、导出**四个面各有一个真实的失败形状：
  缓存键漏租户（不报错、直接返回别人的数据）、消费者不校验信封、
  日志里带别人的行、导出先查全量再在应用里筛。
- **否定缓存也必须分区**：A 租户「查无此物」在 B 租户可能存在。
- **导出核对行数**是唯一廉价的「过滤器写错位置」检测手段。

## 4. 错误语义

`ISO_UNREADABLE`、`ISO_SHAPE`、`ISO_VERSION_FIELD`、`ISO_PRINCIPLE`、`ISO_NO_SURFACES`、
`ISO_SURFACE_ID`、`ISO_SURFACE_DUPLICATE`、`ISO_NO_MECHANISM`、`ISO_ENFORCEMENT_POINT`、
`ISO_DEFAULT_ALLOW`、`ISO_NO_TENANT_KEY`、`ISO_NO_PROBE`、`ISO_PROBE_DUPLICATE`、
`ISO_PROBE_POSITIVE_ONLY`、`ISO_PROBE_NOT_IN_CI`、`ISO_SURFACE_NOTES`、`ISO_SURFACE_MISSING`、
`ISO_RLS_NOT_FORCED`、`ISO_NO_SESSION_TENANT`、`ISO_APPLICATION_FILTER_ONLY`、
`ISO_PERMISSION_UNKNOWN`、`ISO_CROSS_TENANT_SINGLE_PERSON`、`ISO_FORCED_NOTES`、
`ISO_CACHE_UNSCOPED`、`ISO_CACHE_SHARED`、`ISO_NEGATIVE_CACHE_SHARED`、`ISO_CACHE_NOTES`、
`ISO_TOPIC_UNSCOPED`、`ISO_CONSUMER_TRUSTS_PRODUCER`、`ISO_CROSS_TENANT_FANOUT`、
`ISO_MESSAGING_NOTES`、`ISO_LOG_UNSCOPED`、`ISO_LOG_PAYLOAD`、`ISO_LOG_AGGREGATION_UNGATED`、
`ISO_LOG_NOTES`、`ISO_EXPORT_FILTER_LATE`、`ISO_EXPORT_MULTI_TENANT`、`ISO_EXPORT_UNVERIFIED`、
`ISO_EXPORT_NOTES`、`ISO_NO_EVIDENCE_POLICY`、`ISO_EVIDENCE_NOTES`、`ISO_TABLE_WITHOUT_RLS`、
`ISO_CROSS_TENANT_REFERENCE`、`ISO_AUDIT_CLASS_UNKNOWN`、`ISO_AUDIT_CLASS_TOO_WEAK`、
`ISO_GENERATED_MISSING`、`ISO_GENERATED_DRIFT`、`ISO_GENERATED`。

运行期拒绝码：`NO_TENANT_CONTEXT`、`CROSS_TENANT_READ`、`CROSS_TENANT_WRITE`、
`CACHE_KEY_UNSCOPED`、`TOPIC_TENANT_MISSING`、`CONSUMER_TENANT_MISMATCH`、
`LOG_TENANT_MISSING`、`LOG_FOREIGN_ROW`、`EXPORT_MULTI_TENANT`、`EXPORT_FILTER_LATE`、
`OBJECT_PREFIX_DENIED`、`JOB_TENANT_MISSING`、`PROBE_MISSING`、`PROBE_DID_NOT_DENY`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify tenant-isolation --repo .
python3 scripts/render-isolation.py --check
python3 scripts/isolation-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| **反例** | 不对属主强制行级安全时：正向断言通过 **且** 租户 A 读到租户 B 的行——同一个测试里两条断言 |
| 探针 | 8 个探针全部执行且全部断言拒绝；声明不存在的探针 → `PROBE_MISSING`；探针没能拒绝 → `PROBE_DID_NOT_DENY` |
| 数据库 | 无租户上下文报错；跨租户读/写被拒；本租户只见自己；仅持跨租户权限者见全部 |
| 缓存 | 同名键在不同租户下互不影响；无租户键被拒；否定缓存按租户分区 |
| 消息 | 无租户不能发布；消费者租户不符即拒；同租户正常 |
| 日志 | 无租户字段被拒；带别人的行被拒；带自己的行正常 |
| 导出 | 跨租户导出被拒；应用层过滤被拒；行数核对能发现混入的外租户行 |
| 对象存储 | 跨前缀读取被拒；自己前缀可读 |
| 后台任务 | 无租户任务被拒；绑定租户的任务只处理本租户 |
| 拒绝 | 48 条规则各有用例：探针只断言正向、探针复用、探针不在 CI、隔离面默认放行、属主豁免 RLS、无会话租户、仅应用层过滤、缓存键无租户、否定缓存共享、消费者不校验、日志不脱敏、导出后过滤、审计类别降级…… |
| 跨批次 | B13 关掉某表 RLS → `ISO_TABLE_WITHOUT_RLS`；B13 取消属主强制 → `ISO_RLS_NOT_FORCED`；B13 清空会话变量 → `ISO_NO_SESSION_TENANT`；B24 允许跨租户引用 → `ISO_CROSS_TENANT_REFERENCE`；B19 撤掉 `cross_tenant_data.read` 双人 → `ISO_CROSS_TENANT_SINGLE_PERSON` |
| 失败关闭 | 模型坏到无法生成契约时 `ISO_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `isolation-smoke.py` 31 项断言；负向控制新增 27 个 B31 场景，共 425 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-isolation.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **探针跑的是模型，不是真实系统**。`Database` 是一个内存列表，
  它证明的是「这套规则自洽且拒绝形状正确」，**不是「我们的 Postgres 真的开了 RLS」**。
  真实的探针必须连真实数据库、真实缓存、真实消息队列跑，
  并且**在生产同构的环境里**跑——这属于实现批次，本批次只把契约固定下来。
  这是本批次最大的局限，写在这里以免有人把绿灯当成隔离已经成立。
- **搜索索引的探针是退化的**。它复用了数据库的按租户 select，
  因为本批次没有搜索引擎模型；一个共享索引 + 查询时过滤的真实实现
  **不会被这个探针发现**。
- **没有建模「租户内的授权」**。本批次只管跨租户；同一租户内不同用户能看到什么
  属于 B19。两者混淆是另一类常见泄漏，但不在这里。
- **日志脱敏是一个布尔值**。真实脱敏需要字段级规则、结构化日志约束、
  以及对异常堆栈里携带的对象的处理——后者是最常见的泄漏路径，本批次没有覆盖。
- **`Session` 可以自己声明 `cross_tenant_granted=True`**。
  参考实现里没有权限校验层，那属于 B19；这意味着**这个模型信任调用方的会话对象**。
- **没有覆盖旁路**：备份、只读副本、BI 直连、数据科学导出、
  以及 DBA 的交互式会话——这些是真实世界里绕过 RLS 最常见的路径，
  本批次的 8 个面**都不包含它们**。

## 9. 数据迁移

无。真实落地时需要为每张既有表补 RLS 策略并回填 `tenant_id`，属于实现批次。

## 10. 证据与审查

`evidence/B31/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B30 与 B29 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **写一个隔离测试** | 只断言「我看得到我的」→ 删掉过滤器测试照样绿 | 每个隔离面的探针必须断言拒绝；反例演示写进运行期证据 |
| 应用以属主身份连库 | 「我们有 RLS」+「我们是属主」= 没有 RLS | 对属主强制；B13 每张表的 `force_for_owner` 被交叉校验 |
| 忘记 WHERE 子句 | 返回全部而不是报错 | 无租户上下文的查询抛 `NO_TENANT_CONTEXT` |
| **按用户 ID 做缓存** | 两个租户有同名用户 → 静默返回别人的数据 | 缓存键必须含租户；否定缓存同样分区 |
| 共享消息主题 | 生产者带了租户、消费者没看 | 消费者必须校验；不符即拒 |
| 导出大表 | 应用层过滤被「优化」成分页 → 最后一页带出别人的行 | 过滤必须在查询里；一次一个租户；核对行数 |
| 错误日志 | 堆栈里带了别人的订单 | 日志必须带租户、载荷脱敏、带外租户行即拒 |
