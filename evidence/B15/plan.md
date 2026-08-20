# B15 plan — 现有项目订单迁移架构

Batch: 现有项目订单迁移架构 · Wave W01 · Skill `pay-service-migration-architecture` · depends_on: [B14, B13]

## 1. 范围

原则只有一句话，但它是承重的：**业务订单留在原项目，只迁移支付事实与支付动作。**
本批次把这句话变成四期可执行的迁移计划，外加一套能被运行的双写模型。

1. `governance/migration-plan.json`：所有权切分、绑定方式、适配层契约、双写规则、
   回填策略、切换与 kill switch、4 期迁移（每期带进入/退出条件、回退动作与证据闸门）。
2. `tools/paygov/migration.py`：迁移门禁（54 条规则），含跨事实源检查：
   适配层操作必须存在于 B11 的 API 契约；legacy 侧概念不得出现在 B08 的领域表里。
3. `libs/migration/reference/dualwrite.py`：**可执行的迁移模型**——
   渠道调用计数器、双存储、分歧检测、幂等可续跑的回填。
4. `tools/paygov/miggen.py` + `scripts/render-migration.py`，生成
   `contracts/migration/plan.json` 与 `docs/migration/MIGRATION_RUNBOOK.md`（含 Mermaid 阶段图）。
5. `scripts/migration-smoke.py`：22 项运行期断言，7 组场景。
6. `tools/tests/test_b15_migration.py`：81 个用例。

## 2. 受影响组件

`governance/{migration-plan,ssot-registry}.json`、`tools/paygov/{migration,miggen,registry}.py`、
`libs/migration/`、`scripts/{render-migration,migration-smoke}.py`、`contracts/migration/`、
`docs/migration/`、`tools/tests/{test_b15_migration.py,support.py}`、
`scripts/negative-controls.py`（扩至 109 个场景）。无数据库变更、无服务代码。

## 3. 领域接口与数据契约

- **所有权切分**：旧系统保留 `business_order / order_item / sku / inventory / fulfilment /
  shipping_address / customer_profile / promotion / invoice_content`；
  平台拿走 `payment_intent / payment_attempt / refund / dispute / subscription /
  ledger_* / recon_*`。两侧不得有交集，且 legacy 侧概念**不得**在平台的领域表里出现（FF-03）。
- **绑定**：只通过 `(project_id, external_reference)`。平台不存订单号以外的任何订单信息，
  也**不得连接旧系统数据库**（FF-01）。
- **适配层住在旧系统里**，由旧系统团队拥有。放进平台仓库会让平台重新开始理解订单。
  4 个操作全部映射到 B11 的真实 API 操作，幂等键一律来自 `external_reference`——
  每次重试生成新键就是第二次扣款。
- **双写 = 双记录，不是双扣款**：任何一期里，一笔支付对渠道的调用**只有一次**。
  非权威侧写的是同一笔事实的镜像。这是本批次最重要的一条，
  在门禁（`provider_calls_per_payment == 1`）与参考模型（计数器）两处都被强制。
- **分歧检测**：比对 `amount_minor / currency / status / external_reference`，
  15 分钟窗口，预算 0.1%，超预算或出现任何金额类分歧即中止推进，分歧落到 `recon_exception`。
- **四期**：`legacy_only` → `dual_write_legacy_authoritative` →
  `dual_write_platform_authoritative` → `platform_only`。
  每期恰好一个系统对支付事实权威；每期都有进入条件、退出条件、**保全支付事实的回退**与证据闸门。
- **回填**：对旧系统只读、幂等、可断点续跑（断点字段 `legacy_payment_id`），
  校验用**总额**而不是抽样——抽样能证明存在，证明不了守恒。
- **切换粒度是项目**，不是全局；kill switch 60 秒内生效并留审计事件。

## 4. 错误语义

`MIG_UNREADABLE`、`MIG_VERSION_FIELD`、`MIG_SHAPE`、`MIG_PRINCIPLE`、`MIG_OWNERSHIP`、
`MIG_OWNERSHIP_OVERLAP`、`MIG_LEGACY_IN_PLATFORM`、`MIG_PLATFORM_MISSING`、`MIG_BINDING`、
`MIG_LEGACY_DB_ACCESS`、`MIG_ADAPTER_OWNER`、`MIG_ADAPTER_LOCATION`、
`MIG_ADAPTER_OPERATIONS`、`MIG_ADAPTER_OPERATION`、`MIG_ADAPTER_IDEMPOTENCY`、
`MIG_ADAPTER_LEAK`、`MIG_ADAPTER_FORBIDDEN_LIST`、`MIG_DOUBLE_CHARGE`、`MIG_DIVERGENCE`、
`MIG_DIVERGENCE_ABORT`、`MIG_DUAL_WRITE_POLICY`、`MIG_BACKFILL`、`MIG_BACKFILL_WRITES`、
`MIG_BACKFILL_VERIFICATION`、`MIG_CUTOVER_GRANULARITY`、`MIG_KILL_SWITCH`、
`MIG_PHASE_DUPLICATE`、`MIG_PHASE_ORDER`、`MIG_PHASE_CRITERIA`、`MIG_PHASE_EVIDENCE`、
`MIG_PHASE_NOTES`、`MIG_WRITE_MODE`、`MIG_AUTHORITY`、`MIG_ROLLBACK`、
`MIG_ROLLBACK_DESTRUCTIVE`、`MIG_GENERATED_MISSING`、`MIG_GENERATED_DRIFT`、`MIG_GENERATED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify migration-plan --repo .
python3 scripts/render-migration.py --check
python3 scripts/migration-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 4 期全部有进入/退出条件、证据闸门、保全事实的回退；4 个适配层操作全部存在于 API 契约 |
| 重复 | **四期各跑一遍，渠道调用次数恒为 1**；同一笔支付第二次调用渠道必须抛错 |
| 回退 | 从最后一期逐期回退到第一期，两侧记录数不变；回退路径与阶段顺序严格相反 |
| 越界 | `sku / item_count / shipping_address / product_name` 写入任一存储必须抛 `BusinessDataLeak` |
| 分歧 | 两侧一致时零分歧；金额被改后必须精确定位到 `amount_minor` |
| 回填 | 重跑不产生新写入；崩溃后从断点续跑结果与干净跑逐行相同；改一分钱后 count 仍对但 totals 必须失败 |
| 拒绝 | 54 条规则各有用例：两次渠道调用、给平台开旧库权限、适配层透传 SKU、自己造幂等键、破坏性回退、回填写旧库、分歧检测不看金额、全局切换…… |
| 失败关闭 | 计划坏到无法生成 runbook 时给出 `MIG_GENERATED` 而非崩溃 |
| 运行期 | `migration-smoke.py` 22 项断言；负向控制新增 9 个 B15 场景，共 109 个场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-migration.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **这是一份迁移架构，不是一次迁移**。没有真实的旧系统、没有真实的数据、
  没有真实的渠道。`libs/migration/reference/dualwrite.py` 验证的是**这套规则自洽且能挡住已知错误**，
  它证明不了任何一次真实迁移是安全的。
- **适配层没有实现**，因为按设计它住在旧系统仓库里，不在本仓库。
  本批次给出的是它的**契约**（操作映射、幂等键来源、禁止透传字段）。
  谁来写、怎么测，属于接手项目的团队。
- **分歧检测只在模型里跑过**。真实的比对需要两侧的读取路径、时钟对齐与采样策略；
  15 分钟窗口与 0.1% 预算是**待验证的初值**，不是实测结论。
- **回填模型的"崩溃"是抛异常，不是进程被杀**。真实的断点续跑还要处理
  部分写入、事务边界与并发实例，这些属于有数据库的批次。
- **`MIG_LEGACY_IN_PLATFORM` 只比对表名字符串**。如果旧系统的概念以别的名字混进平台
  （例如 `line_items` 而不是 `order_item`），这条规则抓不到。
  真正的防线是 B08 的 `DOMAIN_BUSINESS_FIELD` 字段名黑名单，两者互补但都不完备。
- **没有对 P0「影子期」做任何流量层面的建模**：影子流量怎么产生、怎么保证不触发渠道，
  取决于旧系统的实现，本批次只能规定「平台在 P0 不调用渠道」。

## 9. 数据迁移

无。本批次只产出迁移**计划**与可执行模型。

## 10. 证据与审查

`evidence/B15/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B13、B14 完成文件哈希。
**本批次是 W01 的最后一个批次**：W01（B08–B15）到此全部完成。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 迁移期两个系统同时在处理支付 | 「双写」被实现成两次渠道调用 → 客户被扣两次（AC-01、CTRL-003） | `provider_calls_per_payment == 1` 是硬性规则；参考模型用计数器在四期上逐一验证；负向控制场景「dual write turned into two provider calls」 |
| 适配层是订单数据最容易越界的地方 | 平台重新开始理解商品与库存（NN-01、FF-03） | 透传字段黑名单 + `MIG_ADAPTER_LEAK` + 两侧存储在写入时就拒绝订单字段 |
| 迁移期最容易「先给平台开个只读库权限」 | 只读凭据今天，明天就是一个 JOIN（FF-01） | `legacy_database_access.allowed` 必须为 false，且必须写明业务上下文如何传入 |
| 出事时要快速回退 | 回退把另一侧记录删掉 = 在压力下做第二次迁移 | 每期回退必须 `payment_facts_preserved: true`；模型在回退时断言两侧记录数不变 |
| 适配层重试时容易新生成幂等键 | 一次超时变成两笔支付（NN-04） | 幂等键必须来自 `external_reference`；`MIG_ADAPTER_IDEMPOTENCY` + 负向控制 |
| 回填会被重跑 | 重跑产生重复记录，或写坏旧系统 | 回填必须幂等、可续跑、对旧系统只读；校验必须含总额 |
| 「切过去看看」 | 全局切换没有小爆炸半径也没有安全回退 | 切换粒度必须是项目；kill switch 60 秒内生效并留审计事件（NN-11） |
