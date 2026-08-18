# B00 plan — 项目章程与仓库引导

Batch: 项目章程与仓库引导 · Wave W00 · Skill `pay-program-foundation` · depends_on: []

## 1. 范围

把“业务边界、交付目标、默认部署模式、风险接受原则、不可绕过的安全红线”从散落的
包级政策文档，转化为**本仓库中可执行、可回归、可审计的强制物**：

1. 人类可读章程：`docs/charter/PROGRAM_CHARTER.md`、`RISK_ACCEPTANCE_POLICY.md`、`DELIVERY_MODEL.md`。
2. 机器可读单一事实源：`governance/project-config.json`、`governance/non-negotiables.json`、
   `governance/module-registry.json`。
3. 强制执行工具链：`tools/paygov`（零第三方依赖，Python 3.10+ 标准库）。
4. 回归测试：`tools/tests/`，覆盖正常、拒绝、超时、重复与并发路径。
5. 仓库引导：目录骨架、`.gitignore`、`.gitattributes`、`CODEOWNERS`、`LICENSE`、
   `README.md`、`SECURITY.md`、`Makefile`、证据脚本。

## 2. 受影响组件

本批次不引入运行时服务代码。受影响的是仓库治理面：`docs/charter/`、`governance/`、
`tools/`、`scripts/`、根级仓库元数据，以及 `apps|services|connectors|libs|contracts|platform`
的空目录骨架（其所有权与依赖规则已在 `module-registry.json` 中声明并被测试强制）。

## 3. 领域接口与数据契约

- `paygov` 校验器契约：`validate(root: Path, budget: Budget) -> list[Problem]`。
  `Problem` 字段稳定：`code`、`where`、`message`、`rule`、`context`；输出按
  `(code, where, message)` 全序排序，保证重复运行字节一致。
- CLI 退出码契约：`0` 通过、`2` 存在治理问题、`3` 校验器无法完成。
  **不存在**“通过但有告警”的退出码——NN-12 禁止。
- 版本策略：三个 governance 文件均带 `schema_version`（语义化版本），
  破坏性字段变更必须升主版本并附 ADR（B02）。

## 4. 命令

```bash
python3 -m unittest discover -s tools/tests -t . -v      # 回归测试
python3 -m tools.paygov.cli verify-all --repo .          # 治理门禁
python3 -m tools.paygov.cli list-validators --repo .     # 已注册校验器
python3 .payment-platform/skill-package/scripts/orchestrate.py validate B00 --repo .
scripts/record-commands.py B00 --spec evidence/B00/commands.spec.json
scripts/make-completion.py B00 --artifacts evidence/B00/artifacts.json ...
```

## 5. 测试策略

| 路径 | 覆盖方式 |
| --- | --- |
| 正常 | 真实仓库与固件仓库均通过全部校验器（`*HappyPath`） |
| 拒绝 | 逐条红线的负向变异：储值/资金池、原始卡数据、字面量密钥、非 WebAuthn、关闭四眼、浮点金额、同人执行与复核、生产环境出证据、跨层依赖、依赖环、表所有权冲突、业务订单表入库 |
| 超时 | `Budget(seconds=0)` 触发 `BudgetExceeded`，CLI 退出码 3，`ok=false` |
| 重复 | 同一输入重复 5 次运行字节一致；失败输出同样字节一致 |
| 并发 | 8 线程并发运行 `verify-all`，结果集合大小必须为 1（无共享可变状态） |
| 安全 | 密钥模式扫描（私钥块、AWS、PSP live/test、通用赋值、JWT）与浮点金额扫描 |

## 6. 回滚

本批次为纯增量：新增文件 + 首个 git 提交。回滚方式为 `git revert` 该提交；
不涉及数据库迁移、运行时配置或外部副作用，回滚无数据风险。

## 7. 威胁变化

新增资产：`governance/*.json`（被篡改可放宽全部红线）。
控制：`CODEOWNERS` 要求架构/安全复核 + `paygov` 在 CI 中对自身配置回归校验 +
`non-negotiables.json` 与上游政策条目数强制一致（防止悄悄删红线）。
剩余风险登记推迟到 B02 的 `governance/threat-model.json`。

## 8. 数据迁移

无。本批次不创建任何数据库对象。

## 9. 可观测性

治理门禁输出为确定性 JSON，可直接被 CI 归档与 diff；
`evidence/B00/security/governance-report.json` 为本批次的门禁快照。

## 10. 证据与审查

证据见 `evidence/B00/`（plan、commands.ndjson、test-results、runtime、security、traceability）。
执行者 `claude-agent`；独立审查者 `Ethan`（不是本批次实现者），
执行者与审查者不同由 `paygov` 的 `CONFIG_EVIDENCE` 规则强制。
