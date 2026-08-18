# B06 plan — 批次编排与证据框架

Batch: 批次编排与证据框架 · Wave W00 · Skill `pay-evidence-traceability` · depends_on: [B02, B05]

## 1. 范围

在**本仓库内**实现 B00–B127 的依赖解析、ready 判定、证据初始化、完成校验与发布门禁，
并与随包提供的编排器**互相校验**：

1. `tools/paygov/orchestration.py`：独立实现的 `Programme`
   （DAG、环检测、拓扑性、完成校验、ready、release gate）。
2. `scripts/batch.py`：`status/ready/validate/release/graph/crosscheck` CLI，
   其中 `crosscheck` 逐项比对本地实现与随包编排器的结论，不一致即失败。
3. `governance/evidence-policy.json` + `tools/paygov/evidence.py`：证据结构门禁。
4. `tools/tests/test_b06_orchestration.py`（28 例）、`test_b06_evidence.py`（14 例）。

## 2. 受影响组件

`tools/paygov/{orchestration,evidence}.py`、`governance/evidence-policy.json`、
`scripts/batch.py`、`tools/tests/`、`scripts/negative-controls.py`（扩至 43 场景）、
`evidence/B04/plan.md` 与 `evidence/B05/plan.md`（补齐“威胁变化”章节，由本批次门禁发现）。

## 3. 领域接口与数据契约

- `Programme(root)`：`dependencies/cycles/manifest_is_topologically_sorted/problems/
  valid/completed/ready/status/release_ready`。
- `problems(batch)` 返回**字符串原因列表**，空列表即通过；判定条件与随包编排器一致：
  计划体积、命令记录、追踪五段非空、三类证据目录非空、完成文件必需字段、
  提交存在性、执行者≠审查者、时间戳顺序、测试摘要、安全摘要、依赖哈希、产物摘要与路径包含性。
- 证据策略契约：必需文件/目录、必需计划章节（按标题关键字匹配，允许各批次自行编号）、
  必需命令类别（测试摘要、治理门禁、负向控制、超时 fail-closed、幂等、环境指纹）、
  追踪路径键与主体（executor/reviewer）。
- **差分不变量**：两套实现在 `status`、`ready` 与逐批次 `validate` 上必须完全一致。

## 4. 错误语义

`EVIDENCE_FILE`、`EVIDENCE_DIR`、`EVIDENCE_PLAN_SECTION`、`EVIDENCE_COMMAND_CLASS`、
`EVIDENCE_TRACE`、`EVIDENCE_TRACE_DANGLING`、`EVIDENCE_ARTIFACT`、`EVIDENCE_PRINCIPAL`、
`EVIDENCE_UNKNOWN_BATCH`、`EVIDENCE_EMPTY`、`EVIDENCE_VERSION`、`EVIDENCE_SPEC`。

## 5. 命令

```bash
python3 scripts/batch.py graph
python3 scripts/batch.py crosscheck
python3 -m tools.paygov.cli verify evidence --repo .
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 图性质 | 128 批次无环、依赖全部可解析、manifest 本身是拓扑序、B00 无依赖、其余批次均有依赖 |
| 差分 | `crosscheck` 与随包编排器在 status/ready/逐批次 validate 上零不一致 |
| 篡改 | 在合成证据树上逐字段破坏：产物被改、产物被删、产物路径越界、依赖哈希不符、状态非 passed、执行者=审查者、测试失败、跳过关键测试、存在阻断安全问题、接受问题无决策文件、时间戳倒置、非法提交 SHA、缺字段、追踪段为空、命令日志为空、命令缺 exit_code、计划过短、证据目录为空 |
| 传递性 | 依赖失效使被依赖者失效；ready 集合随之收敛；release gate 在未完成时阻断 |
| 结构 | 追踪悬空引用、缺必需文件/目录、计划缺回滚章节、命令谱缺负向控制/缺超时证明、产物清单与完成文件不同步、审查者不符、完成文件对应未知批次 |
| 运行期 | 负向控制扩至 43 场景，新增 4 个 B06 场景（含一个**期望通过**的场景：放宽策略本身不会立刻报错，用于说明策略是可收紧而非可绕过的） |

## 7. 回滚

纯增量；`git revert` 即可。本地编排实现与随包编排器互不依赖，回滚任一方不影响另一方。

## 8. 已知限制（诚实声明）

`crosscheck` 只对**存在完成文件**的批次逐个调用随包编排器；
对其余 122 个批次仅比对聚合结论（status/ready），因为逐个调用会把整棵证据树重复哈希 128 次
而不产生新信息。这一取舍写在此处而不是隐藏在代码里。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B06/`；执行者 `claude-agent`，独立审查者 `Ethan`。
依赖 B02、B05 完成文件哈希写入 `evidence/completion/B06.json`。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 证据判定逻辑进入本仓库 | 单一实现被悄悄放宽后无人察觉（AC-11） | 双实现差分校验；任一方放宽都会产生 mismatch |
| 证据策略成为新的可调参数 | 降低必需命令类别或计划章节以让证据更容易通过（AC-11） | 策略变更受 CODEOWNERS 复核；负向控制证明收紧策略会立即失败 |
| 证据树被复制到临时目录用于测试 | 证据副本被误当作真实证据 | 测试固件全部在 `tempfile` 中且随用例销毁；归档只从仓库内 `evidence/` 生成 |
