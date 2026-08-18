# B02 plan — 架构决策记录与初始威胁模型

Batch: 架构决策记录与初始威胁模型 · Wave W00 · Skill `pay-architecture-toolchain` · depends_on: [B01]

## 1. 范围

1. `docs/adr/0001..0011`：11 条正式 ADR，覆盖单仓边界、业务订单隔离、最小货币单位、
   服务端定责、幂等与 Inbox/Outbox、事实源选型、卡数据零接触、密钥托管、零信任、
   零依赖治理工具链、证据绑定与重新基线。
2. `governance/threat-model.json`：13 个信任域、11 项高价值资产、12 条信任边界、
   10 类攻击者、12 条滥用案例（与上游 `security/THREAT_MODEL.md` 一一对应）、
   5 条剩余风险（含风险所有者、补偿控制、到期日与复审批次）。
3. `tools/paygov/adr.py`、`tools/paygov/threat.py` 两个新校验器。
4. `docs/adr/README.md`、`docs/security/THREAT_MODEL.md` 由源生成，漂移即失败。
5. `tools/tests/test_b02_adr.py`、`test_b02_threat_model.py`：31 个用例。

## 2. 受影响组件

`docs/adr/`、`docs/security/`、`governance/threat-model.json`、`tools/paygov/`、
`tools/tests/`、`scripts/negative-controls.py`（负向控制扩至 21 个场景）。
无运行时服务代码、无数据库对象。

## 3. 领域接口与数据契约

- ADR 契约：文件名 `NNNN-kebab-slug.md`，标题 `# ADR-NNNN: <title>`，
  元数据行 `状态/日期/批次/决策者/关联需求/关联控制/取代`，
  章节 `背景/决策/后果/备选方案/验证`。编号必须稠密且从 0001 开始。
  决策不得原地改写：新决策新建 ADR，旧 ADR 状态改 `superseded` 并由新 ADR 声明取代。
- 威胁模型契约：`zones` / `assets` / `trust_boundaries` / `adversaries` /
  `abuse_cases` / `residual_risks`，全部为非空数组，跨引用必须解析成功。
- **风险接受不变量**（NN-15）：`severity` 不允许 `critical`；`owner` 不允许占位值；
  `compensating_controls` 非空；`due_date` 必须是未来日期；`review_batch` 必须存在于 manifest。
  任一条不满足即 fail closed。
- 滥用案例与上游文档条目数强制一致，防止悄悄删掉一条攻击面。

## 4. 错误语义

新增稳定错误码：`ADR_FILENAME`、`ADR_TITLE`、`ADR_META`、`ADR_SECTION`、`ADR_STATUS`、
`ADR_DATE`、`ADR_DECIDER`、`ADR_BATCH`、`ADR_REQUIREMENT`、`ADR_CONTROL`、`ADR_NUMBERING`、
`ADR_TOO_SHORT`、`ADR_SUPERSEDED_DANGLING`、`ADR_SUPERSEDES_UNKNOWN`、`ADR_SUPERSEDE_STATUS`、
`ADR_EMPTY`、`THREAT_ASSET`、`THREAT_BOUNDARY`、`THREAT_ABUSE`、`THREAT_ABUSE_ID`、
`THREAT_PARITY`、`THREAT_RISK_SEVERITY`、`THREAT_RISK_OWNER`、`THREAT_RISK_CONTROL`、
`THREAT_RISK_DUE`、`THREAT_RISK_EXPIRED`、`THREAT_RISK_REVIEW`、`THREAT_RISK_LINK`、
`THREAT_ACCEPTED_UNTRACKED`、`THREAT_UPSTREAM_MISSING`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify adr threat-model --repo .
python3 scripts/render-docs.py --check
python3 scripts/negative-controls.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/rebaseline.py
python3 .payment-platform/skill-package/scripts/orchestrate.py validate B02 --repo .
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 11 条 ADR、12 条滥用案例、5 条剩余风险全部通过；生成文档无漂移 |
| 拒绝 | ADR：缺章节、缺元数据、非法状态、未知需求/控制、编号断号、非法文件名、内容过短、superseded 无后继、取代不存在的 ADR、目录为空；威胁模型：例外过期、critical 被接受、所有者占位、无补偿控制、复审批次不存在、滥用案例被删、缺缓解批次、未知攻击者、accepted 无风险台账、资产引用未知模块、边界引用未知信任域、上游文档缺失 |
| 时间 | 用固定 `today=2026-08-18` 保证确定性；另用 `today+400d` 证明过期例外会失败 |
| 超时 | `--budget-seconds 0` 时两个新校验器均返回 3 |
| 重复 | `verify-all` 与 `render-docs --check` 重复运行结果一致 |
| 运行期 | 21 个负向控制场景（新增 6 个 B02 场景）在真实 CLI 上验证 fail closed |

## 7. 回滚

纯增量文件 + 提交；`git revert` 即可。重新基线会把 B00/B01 的证据重新绑定到新提交。

## 8. 威胁变化

本批次**产生**威胁模型本身。新增资产 `AS-11 治理单一事实源`：被篡改可静默移除红线覆盖，
控制为 `CODEOWNERS` 复核 + 上游条目数校验 + 生成文档漂移检测。
剩余风险 `RR-05` 诚实记录了“证据由单一自动化执行者产生”的问题，
补偿控制为 executor≠reviewer 强制、完成文件可复算、21 项运行期负向控制。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B02/`；执行者 `claude-agent`，独立审查者 `Ethan`。
依赖 B01 完成文件的哈希写入 `evidence/completion/B02.json`。
