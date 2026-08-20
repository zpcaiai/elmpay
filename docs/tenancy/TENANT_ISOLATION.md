<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/tenant-isolation.json
     Regenerate with: python3 scripts/render-isolation.py -->

# 租户隔离验证（B31）

隔离必须**被证明**，不能被声明。本批次要求每一个隔离面都有一个**断言「另一个租户看不到」**的探针——只断言「本租户看得到」的测试对隔离一无所知，因为把过滤器整个删掉它照样通过。另外三条同样是被现实教出来的：**最危险的泄漏面不是数据库**——所有人都会给数据库加行级安全，泄漏发生在缓存键漏了租户、消息主题被多个租户共用、日志里带了别人的行，因为「那不是数据库」，于是没人用同样的纪律对待它；**忘记 WHERE 子句必须是不可能的**——没有租户上下文的查询要报错，而不是返回全部；**应用层过滤不算隔离**——它是一行可以被下一个人删掉的代码，而删掉之后所有正向测试仍然全绿。

## 隔离面与探针

| 隔离面 | 机制 | 强制点 | 默认 | 租户键 | 探针（断言拒绝） |
| --- | --- | --- | --- | --- | --- |
| `database_rows` | row_level_security | database | deny | `tenant_id` | `probe_rls_denies_other_tenant` |
| `object_storage` | prefix_scoped_credentials | storage | deny | `tenant_id` | `probe_object_prefix_denies_other_tenant` |
| `cache` | tenant_scoped_key | application | deny | `tenant_id` | `probe_cache_key_collides` |
| `message_topics` | tenant_in_envelope | messaging | deny | `tenant_id` | `probe_consumer_rejects_foreign_tenant` |
| `logs` | tenant_field_required | observability | deny | `tenant_id` | `probe_log_rejects_foreign_row` |
| `exports` | query_side_filter | application | deny | `tenant_id` | `probe_export_scoped_to_one_tenant` |
| `search_index` | tenant_partitioned_index | search | deny | `tenant_id` | `probe_search_denies_other_tenant` |
| `background_jobs` | tenant_bound_job_context | application | deny | `tenant_id` | `probe_job_rejects_missing_tenant` |

- **`database_rows`**：数据库行：行级安全在数据库侧强制，且对表属主同样生效（FORCE ROW LEVEL SECURITY）——否则应用连的那个账号往往正好是属主。
- **`object_storage`**：对象存储：凭证按租户前缀受限，不是靠应用拼路径。
- **`cache`**：缓存：键必须含租户。这是最常见的泄漏面——一个按用户 ID 记忆化的缓存在两个租户有同名用户时就串了，而且它不会报错，只会返回别人的数据。
- **`message_topics`**：消息：主题可以共用，但信封里必须带租户且**消费者必须校验**。只在生产者侧带租户等于没带。
- **`logs`**：日志：每条日志必须带租户字段，且载荷经过脱敏。一条包含别人订单号的错误日志，是一次没人会发现的泄漏。
- **`exports`**：导出：过滤必须写在查询里，不能先查全量再在应用里筛——后者在数据量大时会被人「优化」成分页，然后分页的最后一页带出别人的数据。
- **`search_index`**：搜索索引：按租户分区；共享索引 + 查询时过滤是同一类应用层隔离。
- **`background_jobs`**：后台任务：任务上下文必须绑定租户。跨租户的批处理是最容易「顺手」写成全表扫描的地方。

## 强制控制

- 行级安全对表属主同样生效：是
- 查询必须带租户上下文：是
- 仅靠应用层过滤即可：**否**
- 跨租户权限：`cross_tenant_data.read`（见 B19）

没有租户上下文的查询必须**报错**而不是返回全部。「忘记 WHERE 子句」在这套设定里不是一个可能发生的 bug，而是一次异常。

## 缓存

- 键含租户：是；允许共享命名空间：**否**
- 否定缓存按租户分区：是

否定缓存（「查无此物」）同样必须按租户分区：A 租户查不到的对象，在 B 租户可能存在，共享的否定缓存会把它藏起来。

## 消息

- 信封带租户：是；消费者必须校验：是
- 允许跨租户扇出：**否**

消费者校验是这条控制的全部：生产者带上租户而消费者不看，等于没有控制。

## 日志

- 必须带租户字段：是；载荷脱敏：是
- 跨租户聚合需要权限：是

跨租户聚合查询需要显式权限，且该权限在 B19 是双人控制。

## 导出

- 过滤写在查询里：是；一次导出一个租户：是
- 核对行数：是

每次导出只允许一个租户，且导出后要核对行数——行数核对是唯一能发现「过滤器写在了错误位置」的廉价手段。

## 证据

- 每个隔离面都有探针：是
- 探针必须断言拒绝：是
- 探针在 CI 中运行：是
- 仅正向的测试不构成证据：是

只断言正向可见性的测试不构成隔离证据：把过滤器整个删掉，它照样全绿。

审计事件类别：`data.access`（见 B23）。
