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

```bash
python3 scripts/finish-batch.py B01     # 单个批次出证据并校验
python3 scripts/rebaseline.py           # 按依赖顺序重新产生所有已完成批次的证据
```

`rebaseline.py` 严格按 manifest 的批次顺序执行：依赖的完成文件摘要被写进依赖者，
所以父批次必须先重新出证据。

## 3. 不可绕过的前提

- 重新基线**不会**降低门槛：任何一次重新产生证据都会重新跑全量测试、治理门禁与
  运行期负向控制；有任一失败则不会写出 `status: passed`。
- 重新基线**不是**修改历史：它记录“该批次的产物在当前提交上仍然成立”。
  若产物已被破坏，脚本会失败而不是覆盖。
- `executor` 与 `reviewer` 必须不同；独立审查不因重新基线而免除。

## 4. 目录约定

```text
evidence/
  <Bxx>/
    plan.md                # 范围、契约、命令、测试策略、回滚、威胁变化、迁移
    commands.spec.json     # 该批次要执行并记录的命令（含期望退出码）
    commands.ndjson        # 真实执行记录：时间戳、命令、退出码、耗时、输出摘要
    artifacts.json         # 该批次的产物清单（相对路径）
    traceability.json      # 需求 → 代码 → 测试 → 控制 → 证据
    test-results/          # 测试日志与机器可读摘要
    runtime/               # 运行期证据（环境、覆盖、幂等、超时 fail-closed）
    security/              # 治理门禁报告与负向控制结果
  completion/
    <Bxx>.json             # 完成文件，由脚本生成
```
