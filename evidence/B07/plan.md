# B07 plan — 单一事实源与需求追踪

Batch: 单一事实源与需求追踪 · Wave W00 · Skill `pay-evidence-traceability` · depends_on: [B06]

## 1. 范围

建立需求到架构、代码、测试、控制、运行证据与发布结论的**双向**追踪：

1. `governance/ssot-registry.json`：11 个治理事实源，各自登记所有者、强制它的校验器与其生成物。
2. `tools/paygov/ssot.py`：未登记的治理文件、无校验器的事实源、双生成者、
   生成物缺少 banner、生成物被当作事实源一律 fail closed。
3. `tools/paygov/traceability.py`：构建并校验追踪图，**重点是反向覆盖**。
4. `docs/traceability/MATRIX.md`（生成）与 `scripts/traceability-matrix.py`（机器可读图）。
5. 新增 `PAY-REQ-0051..0053` 与能力 `CAP-18`，补齐 NN-15、CTRL-011/018/019 的反向覆盖缺口
   （这三个缺口正是由本批次的反向覆盖校验发现的）。
6. `tools/tests/test_b07_ssot.py`（13 例）与 `test_b07_traceability.py`（15 例）。

## 2. 受影响组件

`governance/{ssot-registry,requirements,service-boundaries}.json`、
`tools/paygov/{ssot,traceability,render,hygiene}.py`、`docs/traceability/`、
`scripts/traceability-matrix.py`、`tools/tests/`、`scripts/negative-controls.py`（扩至 48 场景）。

## 3. 领域接口与数据契约

- SSOT 条目：`id`、`path`、`batch`、`owner`、`validator`（必须是已注册校验器名）、`generates[]`。
- 追踪图 `build_graph(root)` → `{requirements, rules, controls, adrs, capability_of, batch_evidence}`。
- **前向**：需求 → 能力 → 责任模块 → 控制 → 验证批次 → ADR → 测试 → 证据。
- **反向不变量**（本批次的核心）：
  - 每条红线 `NN-01..NN-15` 必须被至少一条需求认领；
  - 每条控制 `CTRL-001..CTRL-020` 必须被至少一条需求认领；
  - 每个模块必须拥有至少一条需求；
  - 每条 ADR 必须约束至少一条真实存在的需求；
  - 每个已出证据的批次必须认领至少一个已知控制，且其引用的测试文件必须存在。
- 生成物 banner：所有生成文件必须携带 `GENERATED FILE`，否则视为可手改。

## 4. 错误语义

`SSOT_UNREGISTERED`、`SSOT_VALIDATOR`、`SSOT_OWNER`、`SSOT_MISSING`、`SSOT_BATCH`、
`SSOT_DOUBLE_GENERATOR`、`SSOT_GENERATED_MISSING`、`SSOT_BANNER`、`SSOT_GENERATED_IS_SOURCE`、
`TRACE_NO_CAPABILITY`、`TRACE_RULE_UNCOVERED`、`TRACE_CONTROL_UNCOVERED`、
`TRACE_MODULE_UNCOVERED`、`TRACE_BATCH_UNKNOWN`、`TRACE_ADR_ORPHAN`、`TRACE_ADR_DANGLING`、
`TRACE_EVIDENCE_NO_CONTROL`、`TRACE_EVIDENCE_UNKNOWN_CONTROL`、`TRACE_EVIDENCE_TEST_MISSING`。
另将仓库卫生的第三方导入检查由正则改为 **AST 解析**：文档字符串中以 “from/import” 开头的
散文曾造成误报，而 fail-closed 门禁的误报等同于停机。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify ssot traceability --repo .
python3 scripts/traceability-matrix.py --out evidence/B07/runtime/trace-graph.json
python3 scripts/render-docs.py --check
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 53 条需求 / 18 项能力 / 12 条 ADR / 15 条红线 / 20 条控制 / 7 个已出证据批次，反向覆盖 100% |
| 反向拒绝 | 红线失去需求认领、控制失去需求认领、模块失去需求、需求脱离所有能力、需求指向未知批次、ADR 引用不存在的需求、ADR 不约束任何需求 |
| SSOT 拒绝 | 未登记的治理文件、未知校验器、无所有者、登记文件不存在、双生成者、生成物缺 banner、生成物被登记为事实源、非法批次引用 |
| 运行期 | 负向控制扩至 48 场景，新增 5 个 B07 场景 |
| 超时 | `--budget-seconds 0` 返回 3 |
| 确定性 | 追踪图与矩阵重复构建结果一致；矩阵中不得出现 `**未覆盖**` |

## 7. 回滚

纯增量；`git revert` 后重新运行 `scripts/render-docs.py`。
新增的三条需求与一项能力可独立回退，但回退会立刻使反向覆盖校验失败——这正是预期行为。

## 8. 已知限制（诚实声明）

批次证据中的需求 ID 目前是**批次本地**的（`B00-R1` 等），尚未逐条链接到 `PAY-REQ-*`。
本批次强制的是“批次证据必须认领已知控制、且其测试文件真实存在”，
批次本地需求到基线需求的逐条映射留到 B119（合规证据与独立评审门）统一收口。
写在这里而不是含糊带过。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B07/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B06 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 追踪矩阵成为对外可信材料 | 矩阵看起来完整但底层已断链，误导审计与监管（AC-11） | 矩阵由源生成且漂移即失败；反向覆盖缺口会直接渲染成 `**未覆盖**` 并使门禁失败 |
| SSOT 注册表本身成为高价值目标 | 把某个治理文件移出注册表即可让它逃脱校验（AC-11） | `SSOT_UNREGISTERED` 反向扫描 `governance/*.json`；注册表变更受 CODEOWNERS 复核 |
| 生成物可被手工编辑 | 绕过事实源直接改生成结果（AC-12） | 所有生成物强制 banner + 漂移检测；生成物不得同时登记为事实源 |
