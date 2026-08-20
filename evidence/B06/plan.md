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
4. `scripts/{record-commands,test-summary,finish-batch,make-completion}.py`：原子命令记录、
   精确分片合并、受独立审查约束且可回滚的最终化边界。
5. `.ai/rebaseline.py`：唯一受支持的状态、分片迁移与有界启动窗口续跑入口；状态绑定真实
   仓库、当前提交、manifest、批次范围和命令谱，已启动切片会安全完成而非被中途强杀。
6. `tools/tests/{test_b06_orchestration,test_b06_evidence,test_ai_rebaseline}.py`：图、证据原语、
   失败恢复、过期状态和审查阻断测试。

## 2. 受影响组件

`tools/paygov/{orchestration,evidence}.py`、`governance/evidence-policy.json`、
`scripts/{batch,record-commands,test-summary,finish-batch,make-completion}.py`、
`.ai/rebaseline.py`、
`tools/tests/`、`scripts/negative-controls.py`、
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
- 命令记录契约：`commands.ndjson` 与当前命令谱摘要、索引、命令文本、期望退出码、实际退出码
  和保存输出摘要精确对应；失败切片不追加半成品，完成边界拒绝不完整或乱序记录。
- 分片契约：负向控制和测试运行是两个独立命令族，各自必须为单次未分片运行，或同一分母的
  精确 `1..N`；测试分片之后必须有一次输入顺序、路径和数量都精确的 merge。
- 审查契约：命令成功不产生完成。`evidence/<batch>/review.json` 必须由配置中的独立人类审查者
  提供，且绑定当前 HEAD、manifest、命令谱、最终 trace、产物清单和精确产物哈希；`.ai`
  不生成或绕过它。completion 只以原子替换安装，边界漂移会恢复旧文件或移除新文件。
- 恢复状态契约：`.ai/.state/` 只保存被 Git 忽略的本地游标，并绑定真实仓库和所有输入摘要；
  输入漂移时拒绝恢复。新批次可处于“规范命令谱已迁移、尚无运行 trace/completion”的阶段。

## 4. 错误语义

`EVIDENCE_FILE`、`EVIDENCE_DIR`、`EVIDENCE_PLAN_SECTION`、`EVIDENCE_COMMAND_CLASS`、
`EVIDENCE_TRACE`、`EVIDENCE_TRACE_DANGLING`、`EVIDENCE_ARTIFACT`、`EVIDENCE_PRINCIPAL`、
`EVIDENCE_UNKNOWN_BATCH`、`EVIDENCE_EMPTY`、`EVIDENCE_VERSION`、`EVIDENCE_SPEC`，以及
`EVIDENCE_SHARD_{MALFORMED,RANGE,DUPLICATE,INCOMPLETE,MIXED,MODE,MERGE}`。

## 5. 命令

```bash
python3 scripts/batch.py graph
python3 scripts/batch.py crosscheck
python3 -m tools.paygov.cli verify evidence --repo .
python3 .ai/rebaseline.py status --from B00 --to B33
python3 .ai/rebaseline.py migrate-shards --from B00 --to B33 --shards 4 --dry-run
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
| 分片 | 两个命令族各自精确覆盖 `1..N`；拒绝重复、缺片、越界、混合模式、错误 merge 元数据与额外输入 |
| 原子记录 | 失败切片保留原日志；重试从精确游标继续；旧 spec、乱序记录、被改输出与空范围最终化均失败关闭 |
| `.ai` 恢复 | 路径/HEAD/manifest/范围/命令谱漂移、并发锁、B100 编号、旧日志歧义、dry-run 与新批次阶段 |
| 审查边界 | 缺失、未跟踪、主体不符、无时区时间、空范围/说明、HEAD、最终 trace 或任一输入/产物摘要过期时不写 completion；边界竞态回滚 |
| 运行期 | 负向控制包含 B06 证据绕过场景；策略收紧和门禁删除均有失败关闭证明 |

## 7. 回滚

纯增量；`git revert` 即可。本地编排实现与随包编排器互不依赖。回滚 `.ai` 驱动时同时回滚
命令记录/最终化契约，不能保留一个会调用旧接口的半套恢复工具。

## 8. 已知限制（诚实声明）

`crosscheck` 只对**存在完成文件**的批次逐个调用随包编排器；
对其余 122 个批次仅比对聚合结论（status/ready），因为逐个调用会把整棵证据树重复哈希 128 次
而不产生新信息。这一取舍写在此处而不是隐藏在代码里。

`.ai` 只编排仓库命令谱，不替代独立人类判断；它可以安全停在 `review-blocked`，但不能自行
解除。状态与证据只绑定单一工作树和 HEAD；不提供跨工作树合并、远程调度或审查签名服务。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B06/`；配置中的执行者 `claude-agent`，独立审查者 `Ethan`。本次自动化实现没有
观察到 Ethan 对当前 HEAD 和产物摘要的 `review.json`，因此当前独立复核为 `NOT_RUN`，旧
completion 不能证明本次变更已获批准。依赖 B02、B05 的摘要只会在审查通过后的最终化中写入。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 证据判定逻辑进入本仓库 | 单一实现被悄悄放宽后无人察觉（AC-11） | 双实现差分校验；任一方放宽都会产生 mismatch |
| 证据策略成为新的可调参数 | 降低必需命令类别或计划章节以让证据更容易通过（AC-11） | 策略变更受 CODEOWNERS 复核；负向控制证明收紧策略会立即失败 |
| 证据树被复制到临时目录用于测试 | 证据副本被误当作真实证据 | 测试固件全部在 `tempfile` 中且随用例销毁；归档只从仓库内 `evidence/` 生成 |
| 分片命令只跑一片或重复一片 | 摘要看似成功但没有覆盖全部测试/负向控制 | 两个命令族独立验证精确 `1..N`，测试 merge 校验精确输入与发现单元 |
| 失败续跑把坏记录追加到日志 | 后续成功无法区分真实前缀与失败残留 | 切片先在内存构造并验证，只有整片成功才原子替换命令日志 |
| 自动化冒充独立批准 | 同一执行者既实现又给 completion 签字 | 受 Git 跟踪的 review attestation、主体分离和当前 HEAD/输入/产物全绑定；缺失即阻断 |
| 恢复旧游标到新代码 | 在改变后的命令谱上跳过命令 | 状态绑定真实路径、HEAD、manifest、范围与逐批次命令谱，任一漂移均拒绝恢复 |
