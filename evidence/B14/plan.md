# B14 plan — 服务拆分与依赖规则

Batch: 服务拆分与依赖规则 · Wave W01 · Skill `pay-service-migration-architecture` · depends_on: [B12]

## 1. 范围

B00 的模块注册表说的是**构建期**依赖。B14 说的是**运行期**：
哪些调用是同步的、允许多久、失败时怎么办、以及哪些调用根本不该在资金路径上。

1. `governance/service-topology.json`：11 个部署单元、19 条同步边、2 条异步边，
   每条同步边带超时、重试、熔断、隔板、失败模式与降级说明。
2. `tools/paygov/topology.py`：拓扑门禁（41 条规则），把架构图变成**算术**：
   预算核算、同步环检测、调用深度、隔板、跨模块外键。
3. `tools/paygov/topogen.py` + `scripts/render-topology.py`，生成
   `contracts/topology/graph.json` 与 `docs/architecture/SERVICE_TOPOLOGY.md`（含 Mermaid 图）。
4. `scripts/topology-smoke.py`：29 项运行期断言，含最坏耗时计算、逐依赖故障注入、爆炸半径。
5. `tools/tests/test_b14_topology.py`：65 个用例。

## 2. 受影响组件

`governance/{service-topology,ssot-registry}.json`、`tools/paygov/{topology,topogen,registry,domaingen}.py`、
`scripts/{render-topology,topology-smoke}.py`、`contracts/topology/`、`docs/architecture/`、
`contracts/sql/schema.sql`（生成规则变更，见 §8）、
`tools/tests/{test_b14_topology.py,support.py}`、`scripts/negative-controls.py`（扩至 100 个场景）。

## 3. 领域接口与数据契约

- **调用方式**：`sync` / `async`。同步边必须带超时、重试次数、熔断、隔板、失败模式与降级说明。
- **预算核算**：调用方的 `request_budget_ms` 必须覆盖其同步依赖超时之和；
  同一 `exclusive_group` 内的依赖是**互斥选项**（一次请求只走一个渠道），按最大值计一次。
  同时，调用方给被调方的超时**不得小于**被调方自己的预算——否则调用方会掐断被调方仍在合法进行的工作，然后重试它。
- **同步深度**：最深 3 跳。每多一跳，一次请求失败的概率就乘一次。
- **资金路径失败模式**：tier1 的同步依赖必须 `fail_closed`；
  **唯一例外是渠道调用**——那时 attempt 进入 `unknown` 而不是 `failed`（AC-01），失败模式是 `degrade`。
- **渠道调用区分 `mutating` 与 `query`**：授权/捕获/退款不得重试（重试就是重复扣款）；
  只读查询可以重试。两者的规则是相反的，所以必须显式声明。
- **账本永远不在同步支付路径上**：`payment-core → ledger-service` 是异步边。
  这让「账本慢」永远不等于「支付失败」。
- **配置服务是叶子**：`merchant-config` 没有任何同步依赖。它被 6 个服务同步依赖，
  它的可用性会乘进所有人的可用性里。
- **数据库独占**：服务只能访问自己拥有的表。共享表就是分布式单体的定义。

## 4. 错误语义

`TOPO_UNREADABLE`、`TOPO_VERSION_FIELD`、`TOPO_SHAPE`、`TOPO_POLICY`、`TOPO_NAME`、
`TOPO_DUPLICATE`、`TOPO_MODULE`、`TOPO_RUNTIME`、`TOPO_CRITICALITY`、`TOPO_NOTES`、
`TOPO_SLO`、`TOPO_BUDGET`、`TOPO_SERVICE_MISSING`、`TOPO_DEP_UNKNOWN`、
`TOPO_DEP_UNDECLARED`、`TOPO_DEP_REASON`、`TOPO_CALL_KIND`、`TOPO_DEGRADATION`、
`TOPO_TIMEOUT`、`TOPO_TIMEOUT_BUDGET`、`TOPO_TIMEOUT_TOO_TIGHT`、`TOPO_BUDGET_EXCEEDED`、
`TOPO_RETRY`、`TOPO_CIRCUIT_BREAKER`、`TOPO_BULKHEAD`、`TOPO_FAILURE_MODE`、
`TOPO_FAIL_OPEN`、`TOPO_CONNECTOR_OPERATION`、`TOPO_CONNECTOR_RETRY`、
`TOPO_CONNECTOR_DEGRADATION`、`TOPO_SYNC_CYCLE`、`TOPO_SYNC_DEPTH`、`TOPO_TABLE_ACCESS`、
`TOPO_FOREIGN_KEY_CROSS_MODULE`、`TOPO_SCHEMA_MISSING`、`TOPO_EVENT_UNKNOWN`、
`TOPO_EVENT_PRODUCER`、`TOPO_EVENT_SUBSCRIPTION`、`TOPO_GENERATED_MISSING`、
`TOPO_GENERATED_DRIFT`、`TOPO_GENERATED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify service-topology --repo .
python3 scripts/render-topology.py --check
python3 scripts/topology-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 11 个部署单元全部有 SLO、预算、边界说明；19 条同步边全部有超时/熔断/隔板/失败模式 |
| 算术 | 每个调用方的预算覆盖其同步超时之和（互斥组按最大值）；每个调用方给被调方的超时不小于被调方预算 |
| 拒绝 | 41 条规则各有用例：引入同步环、预算不够、给 mutating 渠道调用加重试、把渠道超时判成失败、tier1 改成 fail open、把账本挪到同步路径、删掉熔断、跨服务读表、重新引入跨模块外键…… |
| 故障注入 | `topology-smoke.py` 逐个打掉依赖，核对声明的失败模式；打印爆炸半径 |
| 失败关闭 | 拓扑坏到无法生成产物时给出 `TOPO_GENERATED` 而非崩溃 |
| 健壮性 | 依赖项不是对象时图分析必须跳过而不是崩溃（本批次修掉的一个真实缺陷） |
| 运行期 | 负向控制新增 9 个 B14 场景，共 100 个场景 |

**本批次门禁抓到并修掉的四个真实问题**：

1. **16 条跨模块外键**。`TOPO_FOREIGN_KEY_CROSS_MODULE` 发现生成的 `schema.sql` 给
   `payment_intent.tenant_id → tenant`（payment-core → merchant-config）等建了数据库外键。
   这会让两个服务永远无法独立迁移、部署或分片。
   **修法是改 B08 的生成器**：跨所有权边界的引用保留列、不建约束，并在 DDL 里写明由谁负责校验。
   门禁改为读**生成的 DDL** 而不是模型——真正会打断服务拆分的是落到数据库里的那条约束。
   这补上了 B13 计划 §8 里记的缺口。
2. **失败模式靠中文关键词匹配**：第一版规则搜「放行」，结果把
   「**不放行**」误判成 fail-open。改成结构化枚举字段 `failure_mode`。
   一个会读错自己输入的控制，比没有控制更糟。
3. **渠道调用一刀切禁止重试**：webhook-ingress 对渠道的**只读查询**被误伤。
   增加 `operation: mutating|query`，两者规则相反且都必须显式声明。
4. **互斥依赖被求和**：payment-core 同步依赖 5 个渠道，但一次请求只走一个。
   第一版把 5 个 1500ms 全加起来得到 7950ms，逼出荒谬的预算。
   增加 `exclusive_group`，组内按最大值计一次。

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-topology.py` 与 `scripts/render-domain.py`。
注意 §8 提到的 `schema.sql` 生成规则变更会改变已生成的 DDL。

## 8. 已知限制（诚实声明）

- **拓扑是声明，不是运行时**。超时、熔断、隔板目前只存在于 JSON 与生成的文档里，
  **没有任何代码读取它们**。让服务框架真正按这份拓扑配置，属于有构建环境的批次。
  换句话说：本批次保证的是「这套参数自洽且有意义」，**不是**「线上就是这么跑的」。
- **`reads_tables` 目前没有任何服务填写**。`TOPO_TABLE_ACCESS` 规则是可用的（有用例覆盖），
  但真实的表访问关系要等服务代码存在后才能声明或自动提取。
  现在它是一道**为将来准备好的门**，不是一次已完成的检查。
- **最坏耗时计算不考虑重试**。`topology-smoke.py` 按超时求最坏路径，
  但 `retries: 1` 的依赖实际最坏耗时是两倍。这会低估 webhook-ingress 与 worker-scheduler
  的最坏情况。**这是一个已知的低估，不要当成安全边界**。
- **SLO 没有与预算做交叉校验**。规则要求两者都存在，但没有检查
  「被调方 p99 + 网络开销 < 调用方给的超时」。补这条需要网络开销模型。
- **爆炸半径只统计一跳同步依赖**，没有做传递闭包，也没有做可用性乘算
  （0.9995^n 那种）。真实的可用性建模属于 SRE 批次。
- **B15 依赖本批次**：现有项目订单迁移架构需要这里的服务边界，
  尤其是 FF-01（连接器直接访问业务库）与 FF-03（业务订单字段进入支付平台）的落地检查。

## 9. 数据迁移

无。但**生成的 `contracts/sql/schema.sql` 发生了变化**：16 条跨模块外键被移除
（列保留，约束不建）。由于尚未执行过任何迁移，这不涉及数据。
一旦有真实数据库，这一变更必须以迁移脚本形式体现。

## 10. 证据与审查

`evidence/B14/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B12 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 服务拆开后，一次支付要跨多个进程 | 同步环让两个服务无法独立部署、扩容或恢复 | `TOPO_SYNC_CYCLE` + `topology-smoke.py` 的无环检查；负向控制场景「synchronous dependency cycle introduced」 |
| 超时容易被写成装饰 | 调用方预算小于依赖超时之和 → 真正生效的是上游截止时间，工作被中途丢弃 | `TOPO_BUDGET_EXCEEDED` / `TOPO_TIMEOUT_TOO_TIGHT` 双向核算；互斥组按最大值 |
| 渠道超时最容易被当成失败 | 客户被扣两次（AC-01、NN-03） | mutating 渠道调用禁止重试 + 降级必须落到 `unknown` + 失败模式必须是 `degrade` |
| 依赖不可用时「先放行再说」 | 平台发出了从未收款的货 | tier1 同步依赖必须 `fail_closed`（结构化枚举，不靠读中文） |
| 账本或对账变慢 | 如果它们在同步路径上，慢就等于支付失败 | 账本是异步边；`test_the_ledger_is_never_on_the_synchronous_payment_path` + 负向控制场景 |
| 跨模块外键 | 两个服务永远无法独立迁移或分片；一个服务的 DDL 变更会锁住另一个 | `TOPO_FOREIGN_KEY_CROSS_MODULE` 读生成的 DDL；B08 生成器改为跨边界不建约束 |
| 一个慢依赖吃掉调用方全部并发 | 单点变慢 → 全站不可用 | 每条同步边必须有隔板；smoke 里做隔板算术 |
