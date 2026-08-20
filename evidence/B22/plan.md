# B22 plan — ASVS、API 与移动安全基线

Batch: ASVS、API 与移动安全基线 · Wave W02 · Skill `pay-secure-coding-audit` · depends_on: [B20]

## 1. 范围

安全基线通常以电子表格的形式存在，而电子表格无法告诉你它声称的控制是否真的存在。
本批次要解决的就是这件事：**把映射做成可解析的**。

1. `governance/security-baseline.json`：3 个标准（ASVS 4.0.3 / API Top 10 2023 / MASVS 2.0）、
   35 条要求、覆盖率策略、8 条明确记录的缺口。
2. `tools/paygov/baseline.py`：基线门禁（33 条规则码）。核心是三条解析：
   - `gate_rule` 引用的规则码必须是**本仓真的会发出**的（与 `rulecov.emitted_codes` 交叉核对）；
   - `test` 引用必须精确到方法（`文件::类::方法`），用 AST 解析核对；
   - 其余必须记为 `accepted_gap`，带负责人、复核批次、理由，且**数量有上限**。
3. `libs/appsec/reference/hardening.py`：**可执行的四条基线**——脱敏、安全响应头、
   CORS、金额解析（外加写操作幂等键与认证检查）。
4. `tools/paygov/baselinegen.py` + `scripts/render-baseline.py`，生成
   `contracts/security/baseline-matrix.json` 与 `docs/security/SECURITY_BASELINE.md`。
5. `scripts/baseline-smoke.py`：24 项运行期断言。
6. `tools/tests/test_b22_baseline.py`：61 个用例。
7. `tools/negative/b22.py`：11 个负向控制场景。

## 2. 受影响组件

`governance/{security-baseline,ssot-registry}.json`、`tools/paygov/{baseline,baselinegen}.py`、
`libs/appsec/`、`scripts/{render-baseline,baseline-smoke}.py`、
`contracts/security/baseline-matrix.json`、`docs/security/SECURITY_BASELINE.md`、
`tools/tests/test_b22_baseline.py`、`tools/negative/b22.py`。
**没有修改任何既有批次的产物**，因此不需要重新基线。

## 3. 领域接口与数据契约

- **一条没有被任何规则或测试执行的安全要求，等于一句话。** 因此每条要求只有三种状态：
  指向真实规则码、指向真实测试方法、或明确记为缺口。没有第四种。
- **`BASE_RULE_UNKNOWN` 是本批次最重要的规则**。合规矩阵腐烂的方式永远一样：
  规则被改名、测试被删除，而表格那一行还写着「已覆盖」。
  这里把引用**解析**掉，于是腐烂变成构建失败，而不是一张绿色的表。
- **测试引用精确到方法**。`tools/tests/test_b22_baseline.py::HardeningReference::test_...`
  会被 AST 解析核对；**改名这些方法会让门禁失败，这是故意的**。
- **缺口有上限（8 条）**。没有上限的「已接受缺口」只是「忽略」的另一种写法。
  每条缺口必须有负责人和复核批次。
- **MASVS 全部记为缺口**，因为本平台没有自有移动应用。
  把不适用的条目标成「符合」，正是这份文件存在的意义所要防止的那种不诚实——
  `BASE_FALSE_COMPLIANCE` 会拦住它。
- **脱敏顺序不是显然的那个**：`Bearer <token>` 必须在 `key=value` 之前处理，
  因为 `Authorization: Bearer eyJ...` 两个模式都匹配，而后者在第一个空格处停止，
  会把 `Bearer` 这个词替换掉、把令牌留在日志里。这条注释写在代码里。
- **本批次的测试需要「像凭据」的字符串**（否则无法证明脱敏有效）。
  这些行用仓库既有的 `paygov:allow-secret-pattern` 标记显式豁免，
  而不是去削弱扫描器——**门禁在开发过程中确实先把这些行拦了下来**，这正是它该做的。

## 4. 错误语义

`BASE_UNREADABLE`、`BASE_SHAPE`、`BASE_VERSION_FIELD`、`BASE_PRINCIPLE`、`BASE_STANDARD_ID`、
`BASE_STANDARD_VERSION`、`BASE_STANDARD_NOTES`、`BASE_STANDARD_UNKNOWN`、
`BASE_STANDARD_UNUSED`、`BASE_REQUIREMENT_ID`、`BASE_REQUIREMENT_DUPLICATE`、`BASE_LEVEL`、
`BASE_APPLICABILITY`、`BASE_TITLE`、`BASE_NOTES`、`BASE_ENFORCEMENT_KIND`、
`BASE_NO_ENFORCEMENT`、`BASE_RULE_UNKNOWN`、`BASE_TEST_MISSING`、`BASE_GAP_WITH_REFS`、
`BASE_GAP_NO_OWNER`、`BASE_GAP_NO_REVIEW`、`BASE_GAP_NO_REASON`、`BASE_COVERAGE_POLICY`、
`BASE_COVERAGE_BELOW_FLOOR`、`BASE_TOO_MANY_GAPS`、`BASE_FALSE_COMPLIANCE`、
`BASE_GENERATED_MISSING`、`BASE_GENERATED_DRIFT`、`BASE_GENERATED`。

运行期拒绝码：`AMOUNT_NOT_INTEGER`、`AMOUNT_NEGATIVE`、`AMOUNT_TOO_LARGE`、`CURRENCY_EXPONENT`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify security-baseline --repo .
python3 scripts/render-baseline.py --check
python3 scripts/baseline-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 35 条要求全部解析通过；27/31 适用要求由规则或测试执行（87%，下限 75%） |
| **映射腐烂** | 指向不存在的规则码 → `BASE_RULE_UNKNOWN`；指向被改名/删除的测试方法 → `BASE_TEST_MISSING` |
| 缺口 | 无负责人、无复核批次、无理由、同时又声称有执行 —— 四种写法各有用例；缺口超过上限被拦 |
| **虚假合规** | 给不存在的移动端标「符合」→ `BASE_FALSE_COMPLIANCE` |
| 覆盖率 | 把所有要求改成缺口 → 同时触发 `BASE_COVERAGE_BELOW_FLOOR` 与 `BASE_TOO_MANY_GAPS` |
| 脱敏 | 真实形状的堆栈（卡号 + API 密钥 + Bearer 令牌）三者全部消失，`declined` 这类有用信息保留；普通长数字不被误伤；Luhn 区分卡号与流水号 |
| 响应头 | 缺失项被列出；完整集合通过；`max-age=0` 的 HSTS 与 `X-Powered-By` 被点名 |
| CORS | 通配符 + 凭据被拒；单独通配符可接受；`null` origin 被拒 |
| 金额 | 浮点、`"12.50"`、`"1e3"`、空串、空格、`None`、`True` 全部被拒；负数与超限各有专属错误码 |
| 请求 | 写操作缺幂等键、缺认证、非 JSON 内容类型都被报出 |
| 失败关闭 | 模型坏到无法生成契约时 `BASE_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `baseline-smoke.py` 24 项断言；负向控制新增 11 个 B22 场景，共 209 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-baseline.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **本批次证明的是「映射真实」，不是「系统安全」**。`ASVS-1.4.1` 指向 `AUTHZ_DEFAULT_DECISION`
  只说明那条规则存在且会触发，不说明真实运行的服务实现了它——
  真实实现在 B4x 之后，届时这些映射要**重新指向实现层的测试**。
- **35 条要求是抽样，不是全量**。ASVS L2 有数百条；这里挑的是与支付平台最相关、
  且**当前仓库真的能证明**的那些。挑选本身没有被任何规则强制，是人的判断。
- **`libs/appsec` 不是运行中的中间件**。脱敏函数没有接进任何日志管道，
  响应头检查没有接进任何服务器——**没有任何东西保证它们真的被调用**。
  这是本批次最大的缺口：控制存在 ≠ 控制在路径上。
- **脱敏是启发式的**。Luhn 通过的 12–19 位数字会被打码，这既会误伤（少见）也会漏（分片写入、
  base64 编码、拆成两行的卡号）。真实系统还需要在采集端做结构化字段级脱敏。
- **覆盖率的分母可以被操纵**：把要求的 `applicability` 改成 `mobile` 就能移出分母。
  目前只有 `BASE_FALSE_COMPLIANCE` 从反方向挡了一半（不许给 mobile 标符合），
  **没有规则阻止有人把后端要求错标成 mobile**——已知缺口，建议在有实现层后按标准原文校验。
- **没有 SAST/DAST/依赖扫描**。本批次是「基线映射」，不是「代码审计工具」；
  真实的 ASVS 验证需要工具链与网络，属于有构建环境的批次。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B22/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B20 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **合规矩阵会腐烂** | 规则改名、测试删除，表格仍写「已覆盖」，审计时才发现 | 引用被解析：规则码对照真实发出的码，测试引用对照 AST |
| 「不适用」被写成「符合」 | 不存在的移动端拿到一张合格证 | MASVS 条目必须是缺口，否则 `BASE_FALSE_COMPLIANCE` |
| 缺口无限增长 | 「已接受」成为「忽略」的委婉说法 | 缺口上限 8 条 + 必须有负责人与复核批次 |
| **异常堆栈是最快的泄露路径** | 卡号、密钥、令牌一次同时进入日志、崩溃上报与工单（AC-09） | 运行期脱敏，且顺序正确（Bearer 先于 key=value） |
| CORS 配错 | 通配符 + 凭据 = 把已认证会话交给整个互联网 | 明确检查并拒绝；`null` origin 同样拒绝 |
| 金额来自文本 | `float("12.50")` 已经在解析那一刻丢了精度 | 只接受整数最小单位，浮点直接拒绝（NN-05） |
| 客户端会重试 | 没有幂等键的写操作在重试时变成重复扣款 | 写操作必须带 `Idempotency-Key`（NN-03） |
