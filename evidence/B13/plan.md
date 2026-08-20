# B13 plan — 数据所有权、分区与租户模型

Batch: 数据所有权、分区与租户模型 · Wave W01 · Skill `pay-events-data-architecture` · depends_on: [B12]

## 1. 范围

B08 说了**有哪些表**。B13 说的是：**谁拥有它、谁能读到某一行、怎么分区、活多久、之后去哪。**

1. `governance/data-architecture.json`：38 张表（37 张受租户隔离、14 张仅追加），
   租户模型、紧急通道、归档策略、未来分片策略。
2. `tools/paygov/data.py`：数据架构门禁（54 条规则），含三处跨事实源一致性：
   表归属 ↔ `module-registry.json`、租户标记 ↔ `domain-model.json`、
   Outbox/Inbox 表 ↔ `event-catalog.json`。
3. `libs/tenancy/reference/isolation.py`：**可执行的行级安全语义模型**。
4. `tools/paygov/datagen.py` + `scripts/render-data.py`，生成
   `contracts/sql/rls.sql`、`contracts/sql/partitions.sql`、`docs/data/DATA_ARCHITECTURE.md`。
5. `scripts/tenancy-smoke.py`：对全部 37 张租户表做同一组跨租户攻击，13 项运行期断言。
6. `tools/tests/test_b13_data.py`：81 个用例。

## 2. 受影响组件

`governance/{data-architecture,ssot-registry,event-catalog}.json`、
`tools/paygov/{data,datagen,registry}.py`、`libs/tenancy/`、
`scripts/{render-data,tenancy-smoke}.py`、`contracts/sql/`、`docs/data/`、
`tools/tests/{test_b13_data.py,support.py}`、`scripts/negative-controls.py`（扩至 91 个场景）。

## 3. 领域接口与数据契约

- **租户模型**：共享库共享表 + **强制**行级安全。
  `tenant_id = current_setting('app.tenant_id')::uuid`，且 `FORCE ROW LEVEL SECURITY`。
  不加 FORCE 时表的属主会绕过策略——而运维脚本正是以属主身份运行的，
  也就是说豁免恰好在最需要隔离的时候生效。
- **会话没有租户 = 拒绝**，不是「返回全部」。参考模型把它实现成抛异常，
  因为把「没有租户」当成「所有租户」正是定时任务导出全表的来源。
- **紧急通道**：`platform_break_glass` 角色，必须留审计事件、必须四眼复核（NN-11）、
  会话最长 60 分钟。没有紧急通道的隔离设计，会在第一次故障时被人用 superuser 绕过。
- **仅追加**：14 张表记录的是「发生过什么」，生成的 DDL 在权限层直接
  `REVOKE UPDATE, DELETE`。`ledger_transaction / ledger_entry / fee_record` 是硬性要求；
  ledger 家族里其余仍可变的表必须写 `mutability_reason` 说明理由。
- **分区**：参考数据不分区；其余按 `created_at` 月度 RANGE 分区，
  让归档变成 `DETACH PARTITION` 而不是 `DELETE`。
- **保留**：热 90 天 / 温 400 天 / 冷按表；财务证据（账本家族、支付意图、退款、争议、对账）
  下限 2555 天（7 年）。
- **归档**：object-storage + parquet + sha256 清单。**归档必须可回读、可校验**——
  写出去再也读不回来的归档等于删除。
- **分片**：现在不分片，但每张租户表的索引与分片键都以 `tenant_id` 打头，
  使将来分片成为搬迁而不是重写。
- **个人数据**：含个人数据列的表必须声明删除策略（`crypto_shred` / `hard_delete` / `anonymise`）。

## 4. 错误语义

`DATA_UNREADABLE`、`DATA_VERSION_FIELD`、`DATA_SHAPE`、`DATA_TENANCY`、`DATA_BREAK_GLASS`、
`DATA_ARCHIVE_POLICY`、`DATA_SHARDING`、`DATA_TABLE_NAME`、`DATA_TABLE_DUPLICATE`、
`DATA_TABLE_UNKNOWN`、`DATA_TABLE_UNSPECIFIED`、`DATA_OWNER`、`DATA_TENANT_FLAG`、
`DATA_RLS_MISSING`、`DATA_RLS_PREDICATE`、`DATA_RLS_FORCE`、`DATA_RLS_EXEMPTION`、
`DATA_MUTABILITY`、`DATA_LEDGER_MUTABLE`、`DATA_LEDGER_MUTABLE_UNJUSTIFIED`、
`DATA_PARTITION`、`DATA_PARTITION_REASON`、`DATA_RETENTION_ORDER`、`DATA_RETENTION_FLOOR`、
`DATA_ARCHIVE_TARGET`、`DATA_INDEX`、`DATA_INDEX_TENANT`、`DATA_SHARD_KEY`、
`DATA_DELETION_STRATEGY`、`DATA_EVENTING_TABLE`、`DATA_EVENTING_OWNER`、
`DATA_GENERATED_MISSING`、`DATA_GENERATED_DRIFT`、`DATA_GENERATED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify data-architecture --repo .
python3 scripts/render-data.py --check
python3 scripts/tenancy-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 38 张表全部有归属、有租户判定、有分区理由、有保留期、有索引；生成 DDL 与架构一致 |
| 隔离 | 对全部 37 张租户表做同一组跨租户读/写/删攻击，全部为零泄漏 |
| 拒绝 | 54 条门禁规则各有用例：关掉 RLS、不 FORCE、谓词写成 true、账本可变、财务保留期砍到一季度、归属与模块注册表矛盾、索引不以 tenant_id 打头、紧急通道去掉二次审批…… |
| 反证 | `test_without_force_the_owner_sees_every_tenant` **故意复现泄漏**，用来证明 `DATA_RLS_FORCE` 不是装饰 |
| 边界 | 会话没有租户时必须抛异常而不是返回全部 |
| 失败关闭 | 架构坏到无法生成 DDL 时给出 `DATA_GENERATED` 而非崩溃 |
| 运行期 | `tenancy-smoke.py` 13 项断言；负向控制新增 9 个 B13 场景，共 91 个场景 |

**本批次门禁抓到的三个真实问题**（不是构造出来的）：

1. `DATA_EVENTING_TABLE` 发现 **B12 的 inbox 指向了一张不存在的表** `inbox_event`。
   模块注册表里真实的表是 `provider_webhook_inbox`，属主是 `webhook-ingress`。已修正 B12 的目录。
2. `DATA_LEDGER_MUTABLE` 第一版规则用前缀匹配，误伤了 `ledger_account` 与
   `settlement_instruction`——它们是**状态**不是**凭据**。规则收窄到真正记录资金移动的三张表，
   同时新增 `DATA_LEDGER_MUTABLE_UNJUSTIFIED` 要求其余 ledger 家族表写明理由，
   避免"收窄"变成"开后门"。
3. 三张表（`merchant`/`dispute`/`risk_case`）含个人数据但一开始没有删除策略，
   被 `DATA_DELETION_STRATEGY` 拦下。

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-data.py`。
本批次**不执行任何迁移**，因此回滚不涉及数据。

## 8. 已知限制（诚实声明）

- **没有数据库，DDL 从未被执行**。`contracts/sql/{rls,partitions}.sql` 是**契约**，
  不是已验证的迁移。`libs/tenancy/reference/isolation.py` 验证的是**语义**
  （FORCE 的作用、无租户会话必须拒绝、仅追加表拒绝写），
  它**证明不了生成的 SQL 语法正确**，更证明不了 PostgreSQL 会照这个语义执行。
  真正跑起来属于有数据库实例的批次；剩余风险 `RR-02` 在本批次**没有收口**，
  这一点与 B08 计划里"由 B13 负责"的说法相比是**缩水的**，在此明确记录。
- **分区 DDL 只有注释级骨架**。`partitions.sql` 给出的是分区策略与归档命令的形状，
  没有生成 `CREATE TABLE ... PARTITION BY RANGE` 与逐月分区的完整脚本——
  那需要与真实迁移工具（Flyway/Liquibase）对接，属于有构建环境的批次。
- **冷热分层没有实现，只有声明**。`hot_days/warm_days/cold_days` 是契约，
  真正的分层存储、归档任务与回读路径属于 B90/B94/B105。
- **归档完整性只声明了 sha256 清单**，没有实现校验与回读演练。
  「归档可回读」目前是一句话，不是一次演练。
- **个人数据识别是人工枚举**（三张表），不是扫描。真正的数据分类与最小化属于 B105/B106。
- **外键跨模块边界没有检查**。B08 生成 schema 时按引用建外键，
  但没有规则禁止 A 模块的表引用 B 模块的表。这是一个**已知缺口**，
  建议在服务真正拆开时（B14）补上。

## 9. 数据迁移

无。本批次只产出 DDL 契约。

## 10. 证据与审查

`evidence/B13/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B12 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 所有租户的数据放在同一张表里 | 一个忘写的 WHERE 就是跨租户泄漏（NN-09、CTRL-005） | 37 张租户表全部强制 RLS；`tenancy-smoke.py` 对每一张都做跨租户读/写/删攻击 |
| RLS 容易被写成装饰 | 不加 FORCE 时属主豁免，而运维脚本以属主身份运行 | `DATA_RLS_FORCE` + **故意复现泄漏的测试**；负向控制场景「no longer forced for the owner」 |
| 「没有租户」可能被当成「所有租户」 | 定时任务导出全表 | 参考模型把无租户会话实现成抛异常；对应测试与运行期断言 |
| 隔离太严会被人用 superuser 绕过 | 事故现场没人能查数据，于是有人直接上 superuser | 显式紧急通道角色 + 审计事件 + 四眼复核 + 会话过期（NN-11） |
| 账本行可以被 UPDATE | 改一行分录就能抹平差异，且无人知晓（NN-06、CTRL-008） | `DATA_LEDGER_MUTABLE` + 生成 DDL 在权限层 REVOKE；14 张仅追加表逐张验证拒绝写 |
| 保留期是最容易被"优化"掉的成本 | 争议与审计要回溯数年，数据却已删 | `DATA_RETENTION_FLOOR` 财务表 7 年下限；负向控制场景「retention cut to a quarter」 |
| 将来分片时才想起选键 | 需要重写每一个索引而不是搬数据 | 每张租户表的索引与分片键都以 `tenant_id` 打头，`DATA_INDEX_TENANT` / `DATA_SHARD_KEY` 强制 |
