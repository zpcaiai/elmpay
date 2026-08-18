# B01 plan — 需求基线与服务边界

Batch: 需求基线与服务边界 · Wave W00 · Skill `pay-program-foundation` · depends_on: [B00]

## 1. 范围

把“多项目订单接入、支付编排、退款、对账、风控、管理后台与渠道能力”转化为
**可追踪、可验证、可被门禁强制**的需求基线与服务边界：

1. `governance/requirements.json`：50 条 `PAY-REQ-0001..0050`，17 个类别，
   每条绑定责任模块、控制（NN-xx / CTRL-xxx）、验证批次与可测的验收标准。
2. `governance/service-boundaries.json`：7 类外部参与者的所有权与禁止行为、
   17 项能力到需求的映射、10 条禁止流（FF-01..FF-10）。
3. `tools/paygov/requirements.py`、`boundaries.py`、`catalogue.py`、`render.py`、`docs.py`。
4. `docs/requirements/*.md`：由 JSON **生成**的评审文档，漂移即失败。
5. `tools/tests/test_b01_*.py`：23 个用例。

## 2. 受影响组件

治理面：`governance/`、`tools/paygov/`、`tools/tests/`、`docs/requirements/`、`scripts/render-docs.py`。
无运行时服务代码、无数据库对象。

## 3. 领域接口与数据契约

- 需求条目契约：`id`（`PAY-REQ-%04d`，稠密有序）、`title`、`statement`、`category`、
  `priority`（MUST/SHOULD）、`owner_module`、`controls[]`、`verified_by_batches[]`、
  `acceptance`、`status`。
- 边界契约：`external_actors[]`（`owns` / `must_not` 均非空）、`capabilities[]`
  （`owner_module` + `requirements[]` + `inbound_from[]` / `outbound_to[]`）、
  `forbidden_flows[]`（`enforced_by[]` 必须解析到真实红线、控制、测试模块或批次）。
- **双向追踪不变量**：每条需求恰好被一个能力认领；每个能力只引用存在的需求；
  每个模块至少拥有一条需求。任一方向断裂即 fail closed。
- 版本策略：`schema_version` 语义化版本；破坏性字段变更需升主版本 + ADR（B02）。

## 4. 错误语义

新增稳定错误码：`REQ_ID`、`REQ_OWNER`、`REQ_CONTROL`、`REQ_VERIFICATION`、`REQ_TEXT`、
`REQ_CATEGORY`、`REQ_PRIORITY`、`REQ_MODULE_UNCOVERED`、`BOUNDARY_REQ_UNCLAIMED`、
`BOUNDARY_REQ_DOUBLE_CLAIM`、`BOUNDARY_REQ_MISSING`、`BOUNDARY_CAPABILITY`、
`BOUNDARY_EDGE`、`BOUNDARY_ACTOR`、`BOUNDARY_FLOW`、`DOC_DRIFT`、`DOC_MISSING`。

## 5. 命令

```bash
python3 scripts/render-docs.py --check
python3 -m tools.paygov.cli verify requirements service-boundaries generated-docs --repo .
python3 -m unittest discover -s tools/tests -t . -v
python3 .payment-platform/skill-package/scripts/orchestrate.py validate B01 --repo .
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 真实仓库 50 条需求 / 17 能力 / 10 禁止流全部通过；渲染确定性；模块 100% 覆盖 |
| 拒绝 | ID 断号、未知责任模块、缺控制、未知控制、未知验证批次、缺验证、验收过短、未知类别、非法优先级、模块失去需求；需求无人认领、被两个能力重复认领、引用不存在需求、能力属于未知模块、指向未声明参与者、参与者无禁止项、禁止流无强制方式、强制方式指向不存在批次 |
| 超时 | 继承 B00 的 `Budget`；`--budget-seconds 0` 仍返回 3 |
| 重复 | `render-docs.py` 连续两次输出一致；`verify-all` 重复运行字节一致 |
| 并发 | 继承 B00 的 8 线程并发用例（现覆盖 8 个校验器） |
| 漂移 | 修改 JSON 后生成文档必须 `DOC_DRIFT`；删除文档必须 `DOC_MISSING` |

## 7. 回滚

纯增量文件 + 一次提交，`git revert` 即可；无迁移、无外部副作用。

## 8. 威胁变化

新增资产：需求基线与边界定义（被篡改可悄悄移除红线覆盖或让某模块失去责任）。
控制：`CODEOWNERS` 要求架构复核；`enforced_by` 引用完整性校验；
生成文档漂移检测防止“文档写得好看、JSON 已被改坏”。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B01/`；执行者 `claude-agent`，独立审查者 `Ethan`。
依赖 B00 的完成文件哈希写入 `evidence/completion/B01.json` 的 `dependency_hashes`。
