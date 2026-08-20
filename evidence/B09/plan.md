# B09 plan — 金额、币种与精度模型

Batch: 金额、币种与精度模型 · Wave W01 · Skill `pay-domain-money-model` · depends_on: [B08]

## 1. 范围

B08 规定了「金额字段必须是 `money_minor`」这条**类型层**约束。B09 回答类型层无法回答的问题：
一个 `money_minor` 到底代表多少钱、按什么精度、按什么舍入规则、跨币种如何换算。
本批次把这些规则做成**可执行的规范**，而不是文档里的一段话：

1. `governance/currency-metadata.json`：43 个币种的受版本控制元数据
   （ISO 4217 字母码、数字码、最小单位指数 0/2/3、舍入模式、现金舍入粒度、中英文名）。
2. `libs/money/reference/money.py`：**参考实现**。整数最小单位、显式舍入、
   最大余数法分摊、整数标度汇率换算。它是规范的可执行形式，不是生产代码。
3. `contracts/money/vectors.json`：由参考实现生成的**语言中立一致性向量**
   （舍入 40 例、解析/格式化 9 例、分摊 7 例、费率 8 例、换算 6 例）。
   Java 实现（B11 起）必须逐条复现，否则构建失败。
4. `tools/paygov/money.py`：货币元数据门禁，含 **ISO 4217 交叉校验**。
5. `tools/paygov/moneygen.py` + `scripts/render-money-vectors.py`：向量生成与漂移检查。
6. `tools/tests/test_b09_money.py`：57 个用例。

## 2. 受影响组件

`governance/{currency-metadata,ssot-registry,project-config}.json`、
`libs/money/reference/`、`contracts/money/`、`tools/paygov/{money,moneygen,hygiene,registry}.py`、
`scripts/render-money-vectors.py`、`tools/tests/test_b09_money.py`、
`scripts/negative-controls.py`（扩至 59 个场景）。无运行时服务代码。

## 3. 领域接口与数据契约

- **表示**：金额 = `(minor: int64, currency: char(3))`。不存在小数类型；
  `libs/money` 与 `tools/paygov` 的导入允许清单中没有 `float`，
  元数据文件中出现浮点字面量直接被 `MONEY_FLOAT_LITERAL` 拒绝。
- **精度**：`minor_unit_exponent ∈ {0, 2, 3}`（JPY/KRW/VND=0，CNY/USD/EUR=2，KWD/BHD=3）。
  值必须与内置 ISO 4217 表一致——元数据是我们的事实源，但币种精度不是我们能决定的事。
- **舍入**：默认 `half_even`；同时支持 `half_up`、`down`、`up`。
  `divide_round(n, d, mode)` 纯整数运算，负数按符号对称处理。
- **分摊**：`Money.allocate(weights)` 用最大余数法，**保证 `sum(parts) == 原金额`**，
  余数按权重大小、再按索引稳定分配。
- **汇率**：`(rate_numerator: int, rate_scale: int)`，即真实汇率 = `numerator / 10**scale`。
  换算同时处理源、目标币种的指数差，全程整数。
- **格式化/解析**：`Money.parse("19.99","CNY")→1999`；`Money.parse("19.99","JPY")` 抛错
  （JPY 没有小数位）；`Money.parse("1.234","KWD")→1234`。

## 4. 错误语义

`MONEY_UNREADABLE`、`MONEY_VERSION`、`MONEY_SHAPE`、`MONEY_CODE`、`MONEY_NUMERIC`、
`MONEY_DUPLICATE`、`MONEY_EXPONENT`、`MONEY_ROUNDING`、`MONEY_NAME`、
`MONEY_CASH_ROUNDING`、`MONEY_COVERAGE`、`MONEY_SOURCE`、`MONEY_FX_SCALE`、
`MONEY_FLOAT_LITERAL`、`MONEY_VECTORS_MISSING`、`MONEY_VECTORS_DRIFT`、`MONEY_VECTORS`。

`MONEY_VECTORS` 是**失败关闭**通道：当参考实现因输入损坏而无法运行时，门禁必须报告
「向量无法验证」，而不是抛异常。门禁把坏输入变成崩溃，等于放行。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify money-model --repo .
python3 scripts/render-money-vectors.py --check
python3 scripts/render-docs.py --check
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 43 币种全部通过；0/2/3 位小数币种均建模；向量与参考实现逐字节一致 |
| 算术 | `divide_round` 四种模式 × 正负 × 半值边界；分摊余数守恒（`sum(parts)==minor`，含负数与不等权重）；费率与换算跨指数 |
| 解析 | 零小数币种拒绝小数点；三小数币种要求三位；负数、前导零、超长整数 |
| 拒绝 | 浮点字面量、指数越界、指数与 ISO 不符、数字码与 ISO 不符、非法字母码、重复币种、未知舍入模式、删光零小数币种、元数据指向别处、汇率标度非法、缺币种名、现金舍入粒度非法、向量缺失、向量漂移 |
| 失败关闭 | 参考实现被破坏时门禁给出 `MONEY_VECTORS` 而非崩溃（`test_fails_closed_when_the_reference_implementation_cannot_run`） |
| 隔离 | 门禁按 `root` 路径加载参考实现，而不是走 `sys.modules`；夹具仓库不会被真仓库的实现「借尸还魂」 |
| 运行期 | 负向控制新增 6 个 B09 场景，共 59 个场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-money-vectors.py`。
无数据库变更，无迁移。

## 8. 已知限制（诚实声明）

- **参考实现是 Python，生产实现将是 Java**。本批次没有证明 Java 侧的正确性，
  只建立了它必须满足的判据（`contracts/money/vectors.json`）。
  「Java 实现逐条复现向量」这一步在 B11 随构建环境一起完成，缺口沿用剩余风险 `RR-02`。
- **ISO 4217 交叉校验表是人工录入的**，覆盖平台实际结算的 43 个币种。
  它不是完整的 ISO 目录，也不会自动跟随 ISO 修订；新增币种必须同时更新两处，
  这正是设计意图：让单点笔误无法通过。
- **现金舍入（`cash_rounding_minor`）只做了元数据建模**，尚未进入向量。
  真实现金舍入发生在收单终端场景，属于 B2x 线下收单批次。
- 未建模：币种停用/替换（如 HRK→EUR）、历史汇率快照、多币种账户余额。
  分别属于 B13（数据所有权）与 B2x（账本）。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B09/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B08 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 币种元数据成为所有金额语义的源头 | 把 JPY 从 0 位小数改成 2 位，会让每一笔日元金额相差 100 倍，且**不会有任何类型错误**（AC-11） | 内置 ISO 4217 指数/数字码交叉校验 + 一致性向量漂移检查：单改元数据会同时触发两道门 |
| 一致性向量可能被「顺手」改成与实现一致 | 向量沦为实现的复读机，跨语言约束消失 | 向量是生成文件、带 banner、在 SSOT 注册表中登记；手工编辑立刻触发 `MONEY_VECTORS_DRIFT`（负向控制场景） |
| 门禁自身可能因坏输入崩溃 | 崩溃退出码被误当成「工具坏了，先跳过」 | `MONEY_VECTORS` 失败关闭通道；`cli.run` 统一把异常转成退出码 3 |
| 参考实现可能被错误的副本验证 | 夹具仓库改坏了实现却仍然「通过」 | `moneygen._reference` 按 `root` 路径加载，不经过 `sys.modules` |
