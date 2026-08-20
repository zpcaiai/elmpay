# W00 独立对抗式复核与整改记录

- 文档 ID：REVIEW-W00-001
- 版本：1.0.0
- 日期：2026-08-18
- 复核方式：独立复核代理（与实现者不同的执行体），任务是**证伪** B00–B07 的完成性
- 结论（复核时）：**DOES NOT HOLD UP**
- 结论（整改后）：见第 4 节；最终签署仍待人工审查者 `Ethan`

## 1. 为什么记录这份文档

批次门禁的价值取决于它能不能被绕过。这次复核**成功绕过了**它：复核方从源码中删掉了
四条真实的安全规则，整套测试仍然全绿。把这件事写进仓库，而不是修好就算了，是 NN-12
的直接要求——证据必须包含失败过的证据。

## 2. 复核方的主要发现

| # | 严重度 | 发现 |
| --- | --- | --- |
| 1 | blocking | 提交状态下 `verify-all` 退出码 2、3 个测试失败、2 个负向控制未捕获——“306 通过 / 48 全绿”在该提交上不成立 |
| 2 | blocking | B07 的完成文件**自我失效**：`docs/traceability/MATRIX.md` 由 `evidence/completion/*` 生成，写入 B07 完成文件必然使该矩阵漂移，而矩阵又被 B07 以哈希固定，不存在一致状态 |
| 3 | significant | 204 个规则码中 **67 个无法被任何测试或负向控制触发**；复核方删除 `DEV_CONTAINER_PRIVILEGE`、`SECRET_JWT`、`SECRET_STRIPE_TEST`、`CI_UNSAFE_WORKFLOW` 后全套测试仍通过 |
| 3b | significant | `nonneg.py` 只校验 enforcement 测试模块**是否存在**；把两个模块截断为 0 字节后所有门禁仍绿 |
| 4 | significant | 负向控制只断言**进程退出码**，不断言哪条规则触发；一次无关的破坏会让 45 个场景全部“通过”而什么也没证明 |
| 5 | significant | “48 个场景”里只有 45 个真正断言拒绝；其中一个场景把“可以删掉 fail-closed 证明要求”写成了**预期通过** |
| 6 | significant | CI 只跑 `orchestrate.py status`（无论结果如何都退出 0），从不跑 `validate` 或 `crosscheck`——8 个批次全部静默失效时 CI 仍是绿的 |
| 7 | significant | 记录下来的命令退出码从未被重新校验；`completion.tests.passed` 与 runner 的 `summary.json` 无人比对 |
| 8 | minor | `evidence/B07/plan.md` 声称“矩阵漂移即失败”，而交付状态正是在该矩阵上漂移 |
| 9 | minor | “反向覆盖 100%” 是声明层的账面统计，不绑定代码或通过的测试 |

复核方同时确认**没有伪造证据**：117 个产物摘要、85 个命令输出摘要与 tail 全部逐一重算一致，
时间戳单调且与 `duration_ms` 相符；CLI 的退出码契约确实 fail closed；双实现差分是真实的。

## 3. 整改

| 发现 | 整改 |
| --- | --- |
| 1、2 | **打破循环**：`matrix_markdown` 改为只依赖治理事实源（需求、边界、ADR），**不再读取 `evidence/`**；批次证据到控制的映射移入 `evidence/*/runtime/trace-graph.json`（运行期证据，不被哈希固定） |
| 3 | 新增 `tools/paygov/rulecov.py` 与 `rule-coverage` 校验器：任何被发出但无法触发的规则码直接使门禁失败；补齐 68 条规则的真实测试（`tools/tests/test_rule_coverage.py`） |
| 3 | 新增 `scripts/rule-knockout.py`：在临时副本中逐条**抑制**规则并重跑其声称的覆盖测试，测试仍通过即判定该规则不承重。抑制接缝只存在于临时副本，**发行工具链中没有任何环境变量可以静音规则** |
| 3b | enforcement 测试模块必须非空（`NONNEG_ENFORCEMENT_EMPTY`）且必须**指名其所强制的红线**（`NONNEG_ENFORCEMENT_UNNAMED`）；负向控制固件改为复制**真实测试正文**而非空占位 |
| 4 | 负向控制新增 `EXPECTED_CODES` 表：每个拒绝场景必须声明期望触发的规则码并断言其真的触发；未登记期望码的拒绝场景本身判失败 |
| 4 | 基线不干净时**立即中止**并打印基线问题，而不是继续输出 45 个无意义的“通过” |
| 5 | 输出改为 `scenarios=48 rejection_scenarios=46 baseline_and_timeout=2`；“可以删掉 fail-closed 证明要求”的场景改为**预期拒绝**，并在 `tools/paygov/evidence.py` 中以代码级 `MANDATORY_COMMAND_CLASS_IDS` 兜底（策略文件不能删除自己的底线） |
| 6 | CI 的 `evidence-archive` 阶段改为 `batch.py crosscheck` → `validate-all.py` → `archive-evidence.py`；`governance` 阶段也加入 `crosscheck`；新增 `scripts/validate-all.py`（任一声称完成的批次不通过即退出 2） |
| 7 | `Programme.problems()` 新增：每条命令记录的 `exit_code` 必须等于其 `expected_exit_code`；`completion.tests.passed` 必须等于 runner 的 `summary.json`。这些是本地实现**严于**随包编排器的检查，`crosscheck` 用 `extended=False` 做同口径差分，并单独列出 local-only 发现 |
| 8 | 更新 `evidence/B07/plan.md` 的数字与限制声明 |
| 9 | 保留为已知限制：反向覆盖是声明层统计。规则是否承重现在由 knockout 证明，两者是不同的问题，不混为一谈 |

## 4. 整改后的可验证状态

```
python3 -m tools.paygov.cli verify-all --repo .     → ok: true（17 个校验器）
python3 -m unittest discover -s tools/tests -t .    → 352 tests OK
python3 scripts/negative-controls.py                → 46 个拒绝场景，全部断言到具体规则码，0 失败
python3 scripts/rule-knockout.py                    → 211 条规则，207 条经删除验证承重，
                                                       4 条为 CLI 级（接缝不适用，另有直接测试），0 条不承重
python3 scripts/validate-all.py                     → 8/8 批次校验通过
python3 scripts/batch.py crosscheck                 → mismatches=0 local_only_findings=0
```

## 5. 仍然成立的限制

- 本环境无 Maven / 无 Docker，Java 与 compose 从未真实运行（`RR-02`、`RR-06`）。
- 人工独立审查者尚未签署（`RR-05`）。**本次复核由自动化复核代理执行，不能替代人工签署**，
  但它确实做到了实现者自查没有做到的事：删掉真实规则并证明没有人会发现。
