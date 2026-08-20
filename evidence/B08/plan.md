# B08 plan — 支付领域模型与统一语言

Batch: 支付领域模型与统一语言 · Wave W01 · Skill `pay-domain-money-model` · depends_on: [B07]

## 1. 范围

定义租户、项目、商户、渠道账户、支付意图、支付尝试、退款、争议、订阅、账本与对账对象，
并把它们固化为**语言中立的规范模型**，而不是某个框架里的类：

1. `governance/domain-model.json`：14 个实体、133 个字段、43 条不变量，
   封闭类型系统（12 种类型，显式排除 float/double/decimal）。
2. `governance/glossary.json`：62 条统一语言词条（实体 14、状态 36、核心概念 12），中英对照。
3. `tools/paygov/domain.py`：领域模型与统一语言门禁。
4. `contracts/sql/schema.sql`：由模型生成的 PostgreSQL DDL。
5. `docs/domain/{DOMAIN_MODEL,GLOSSARY}.md`：由源生成的评审文档。
6. `tools/tests/test_b08_domain.py`：36 个用例。

## 2. 受影响组件

`governance/{domain-model,glossary,ssot-registry}.json`、`tools/paygov/{domain,domaingen,render}.py`、
`scripts/render-domain.py`、`contracts/sql/`、`docs/domain/`、`tools/tests/`、
`scripts/negative-controls.py`（扩至 53 个场景）。无运行时服务代码。

## 3. 领域接口与数据契约

- 实体契约：`name`（PascalCase）、`module`、`table`（snake_case）、`tenant_scoped`、
  `purpose`、`identity[]`、`fields[]`、`invariants[]`、`states[]`。
- 字段契约：`name`（snake_case）、`type`（封闭类型系统）、`nullable`、`semantics`，
  枚举必须列出取值，引用必须以 `_id` 结尾并指向真实实体。
- **类型层不变量**：
  - 名称含 `amount|price|fee|balance|total` 的字段**必须**是 `money_minor`（NN-05）；
  - `tenant_scoped` 实体**必须**含 `tenant_id`（NN-09）；
  - 实体表必须是其所属模块在模块注册表中真正拥有的表（NN-01）；
  - 字段名不得含 `sku/item/quantity/inventory/stock/shipping_address/...`（NN-01）；
  - 每个实体与每个状态必须在统一语言词表中有词条。
- SQL 生成规则：金额列 `bigint` + 正数 `CHECK`（已捕获/已退款允许 0）、
  枚举列 `text` + `IN (...) CHECK`、币种 `char(3)` + 正则 `CHECK`、
  引用列生成外键、租户隔离实体生成 `tenant_id` 索引与 `ENABLE ROW LEVEL SECURITY`。

## 4. 错误语义

`DOMAIN_UNREADABLE`、`DOMAIN_VERSION`、`DOMAIN_SHAPE`、`DOMAIN_NAME`、`DOMAIN_PURPOSE`、
`DOMAIN_INVARIANT`、`DOMAIN_MODULE`、`DOMAIN_TABLE`、`DOMAIN_TABLE_CONFLICT`、
`DOMAIN_TABLE_OWNERSHIP`、`DOMAIN_GLOSSARY`、`DOMAIN_FIELD`、`DOMAIN_TENANT_SCOPE`、
`DOMAIN_IDENTITY`、`DOMAIN_TYPE`、`DOMAIN_FORBIDDEN_TYPE`、`DOMAIN_MONEY_TYPE`、
`DOMAIN_ENUM`、`DOMAIN_REFERENCE`、`DOMAIN_BUSINESS_FIELD`、`DOMAIN_STATE`、
`DOMAIN_GLOSSARY_SHAPE`、`DOMAIN_GLOSSARY_TERM`、`DOMAIN_GLOSSARY_KIND`、
`DOMAIN_GLOSSARY_DUPLICATE`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify domain-model --repo .
python3 scripts/render-domain.py --check
python3 scripts/render-docs.py --check
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 14 个实体全部通过；批次要求的 13 类对象均已建模；生成 DDL 确定性且带 banner |
| 金额 | 所有货币字段均为 `money_minor`；类型系统中不存在 float/double/decimal；生成 DDL 中不出现 `numeric`/`double precision` |
| 拒绝 | 浮点金额、类型系统外的类型、被禁类型、缺 `tenant_id`、业务订单字段、表所有权不符、未知模块、两实体共用表、非 snake_case 表、非 PascalCase 实体、缺不变量、缺用途、字段重名、identity 不存在、引用悬空、枚举无取值、状态不在状态字段中、实体无词条、模型不可读、版本非法、模型形状错误、实体无字段 |
| 词表 | 词条重复、缺中文名、未知 kind、词表为空 |
| 运行期 | 负向控制新增 5 个 B08 场景（浮点金额、去掉租户隔离、加入业务订单字段、表所有权不符、词表删除实体），共 53 个场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-domain.py` 与 `scripts/render-docs.py`。
尚无数据库实例，回滚不涉及数据。

## 8. 已知限制（诚实声明）

- **生成的 DDL 从未被真实执行**：本环境没有 PostgreSQL 实例，也没有可用的 Maven 仓库，
  因此 `contracts/sql/schema.sql` 在本批次是**契约**而非已验证的迁移。
  实际建表、迁移可回滚性与 RLS 行为由 B13（数据所有权、分区与租户模型）负责，
  该缺口沿用剩余风险 `RR-02`。
- Java 类型未在本批次生成：在没有构建环境的情况下产出无法编译的源码没有价值，
  Java 记录与 API schema 在 B11（API 规范与兼容模型）随契约一起生成。
- 状态机的**合法转移**在本批次只声明了状态集合，转移规则属于 B10。

## 9. 数据迁移

无。本批次只产出 DDL 契约，不执行任何迁移。

## 10. 证据与审查

`evidence/B08/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B07 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 领域模型成为所有下游生成物的源头 | 在模型里悄悄把金额改成浮点或去掉租户隔离，会同时污染 DDL、API 与代码（AC-11） | 类型层强制：货币字段必须 `money_minor`、租户实体必须有 `tenant_id`；两者均有负向控制在运行期证明 |
| 业务订单字段可能被“顺手”加入支付平台 | 平台逐步变成订单中心，扩大合规与故障域（AC-04） | 字段名黑名单 + 表所有权必须与模块注册表一致（NN-01） |
| 统一语言可能在代码与文档间漂移 | 同一概念多个名字，导致告警、运营与账务口径不一致 | 每个实体与状态必须有词条；词表与模型同为事实源，文档由二者生成 |
