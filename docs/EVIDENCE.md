# 证据生命周期

- 文档 ID：DOC-EVID-001
- 版本：1.0.0
- 批次：B01
- 状态：active
- 负责人：payment-platform-security

## 1. 证据绑定到提交

`evidence/completion/<Bxx>.json` 中的每一项都由仓库状态**重新计算**得到，而不是手写：

| 字段 | 来源 |
| --- | --- |
| `commit_sha` | `git rev-parse HEAD` |
| `artifacts[].sha256` | 对工作树文件实际计算 |
| `dependency_hashes` | 对依赖批次完成文件实际计算 |
| `tests` | `scripts/test-summary.py` 的运行结果 |
| `started_at` / `completed_at` | `commands.ndjson` 首尾记录的真实时间戳 |
| `executor` / `reviewer` | `governance/project-config.json`，且两者必须不同 |

## 2. 为什么需要重新基线（re-baseline）

后续批次会合法地修改早期批次的产物：共享校验器新增规则、测试文件增长、
错误码扩充。批次门禁在**校验时**比对产物摘要，因此早期批次的证据必须在新提交上
重新产生，否则只有两种结局——要么证据静默失真，要么 B00 之后所有共享代码被冻结。

仓库只支持一个续跑入口：`.ai/rebaseline.py`。它严格按 manifest 顺序工作，并把本地状态
绑定到仓库真实路径、当前 `HEAD`、manifest 摘要、批次范围以及每个批次的命令谱摘要。
这些绑定任一变化，旧状态都会被拒绝，而不是被猜测性修复。

```bash
python3 .ai/rebaseline.py status --from B00 --to B33
python3 .ai/rebaseline.py migrate-shards --from B00 --to B33 --shards 4 --dry-run
python3 .ai/rebaseline.py migrate-shards --from B00 --to B33 --shards 4
python3 .ai/rebaseline.py resume --from B00 --to B33 --launch-window-seconds 300
```

`migrate-shards` 只接受可无歧义迁移的命令族；负向控制与测试分片必须各自形成精确的
`1..N` 集合，测试分片后必须有一次精确 merge。`resume` 只在启动窗口尚有预算时开始下一条
事务化命令；已启动切片会安全完成而不会在写入中途被强杀，失败切片也不会污染已有
`commands.ndjson`。依赖的完成文件摘要写入依赖者，所以批次必须按拓扑顺序最终化。

## 3. 不可绕过的前提

- 重新基线**不会**降低门槛：任何一次重新产生证据都会重新跑全量测试、治理门禁与
  运行期负向控制；有任一失败则不会写出 `status: passed`。
- 重新基线**不是**修改历史：它记录“该批次的产物在当前提交上仍然成立”。
  若产物已被破坏，脚本会失败而不是覆盖。
- `executor` 与 `reviewer` 必须不同；独立审查不因重新基线而免除。
- 命令全部成功只表示自动化证据已准备好，**不等于完成**。最终化必须显式提供受 Git
  跟踪的 `evidence/<Bxx>/review.json`；`.ai` 不创建该文件，也没有绕过参数。
- `review.json` 必须批准当前批次，并绑定当前 `HEAD`、技能包 manifest、
  `commands.spec.json`、最终 `traceability.json`、`artifacts.json` 以及精确的产物
  路径→SHA-256 映射。审查者、执行者、带时区的审查时间、范围和非空审查说明均由门禁验证。
- 缺失或过期的审查文件会得到 `review-blocked`：命令级进度可保留，但 trace 和 completion
  不会被改写，也不会出现 `status: passed`。
- completion 以原子替换写入，并在写入后重新比对审查文件、依赖完成文件及全部绑定；边界上
  发生漂移时恢复原 completion，若此前没有文件则移除新文件。

## 4. 目录约定

```text
evidence/
  <Bxx>/
    plan.md                # 范围、契约、命令、测试策略、回滚、威胁变化、迁移
    commands.spec.json     # 该批次要执行并记录的命令（含期望退出码）
    commands.ndjson        # 真实执行记录：时间戳、命令、退出码、耗时、输出摘要
    artifacts.json         # 该批次的产物清单（相对路径）
    traceability.json      # 需求 → 代码 → 测试 → 控制 → 证据
    review.json            # 独立人类批准；由审查者提供并绑定当前代码/命令/产物（可缺失）
    test-results/          # 测试日志与机器可读摘要
    runtime/               # 运行期证据（环境、覆盖、幂等、超时 fail-closed）
    security/              # 治理门禁报告与负向控制结果
  completion/
    <Bxx>.json             # 完成文件，由脚本生成
.ai/
  rebaseline.py            # 唯一受支持的迁移、状态与有界启动窗口续跑入口
  .state/                  # 本地可恢复状态；被 Git 忽略，不是证据
```

## 5. 分层不变量（整改后新增）

独立复核暴露出一类反复出现的缺陷：**门禁读取了自己产生的东西**。
它有两种表现，都会造成“没有任何一致状态”：

1. 生成文档依赖 `evidence/`，而该文档又被某批次以哈希固定 → 写入完成文件即让该批次失效；
2. `verify-all` 读取上一次运行留下的测试摘要或命令退出码 → 一次失败会自我延续，
   之后无论怎么修都无法转绿。

因此有两条分层不变量：

| 层 | 何时运行 | 允许读取 | 不允许读取 |
| --- | --- | --- | --- |
| `verify-all`（治理门禁） | 批次写出证据**之前**，且它本身就是被记录的命令之一 | 治理事实源、生成物、证据的**结构** | 测试摘要、命令退出码、完成文件、产物摘要 |
| `Programme.problems()`（批次校验） | 完成文件写出**之后** | 全部，包括测试摘要、退出码、产物与依赖摘要 | — |

生成文档同理：只能是治理事实源的纯函数，不得依赖 `evidence/`。
批次证据相关的统计放在 `evidence/*/runtime/*.json`（运行期证据，不被哈希固定）。
