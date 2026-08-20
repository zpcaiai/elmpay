# B29 plan — 费率、成本、佣金与计量模型

Batch: 费率、成本、佣金与计量模型 · Wave W03 · Skill `pay-routing-pricing` · depends_on: [B28]

## 1. 范围

批次目标最后一句决定了整个批次：「**不得以账面模型替代真实资金结算**」。
这件事从来不是有人决定要做的，它只是一行代码——结算报告到了，
把它写进账面值，于是两个数字一致了。丢掉的是「我们当初以为自己收多少」这个答案，
而那个答案就是一场费用争议的全部内容。

1. `governance/fee-model.json`：4 类费用口径、舍入规则、11 张费率表、
   结算规则、分账、币种、计量。
2. `tools/paygov/fees.py`：费率门禁（57 条规则码），含四条跨批次校验——
   渠道必须在 B26 有绑定、**费率表对应的支付必须在 B27 能真的发生**、
   币种必须在 B09 货币元数据中、审计类别必须是 B23 的 `money.movement`。
3. `libs/pricing/reference/fees.py`：**可执行的计费与结算模型**（全整数，两遍计算）。
4. `tools/paygov/feesgen.py` + `scripts/render-fees.py`。
5. `scripts/fees-smoke.py`：39 项运行期断言。
6. `tools/tests/test_b29_fees.py`：115 个用例。
7. `tools/negative/b29.py`：27 个负向控制场景。

## 2. 受影响组件

`governance/{fee-model,ssot-registry}.json`、`tools/paygov/{fees,feesgen}.py`、
`libs/pricing/`、`scripts/{render-fees,fees-smoke}.py`、
`contracts/pricing/fee-model.json`、`docs/pricing/FEE_MODEL.md`、
`tools/tests/test_b29_fees.py`、`tools/negative/b29.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **`settle()` 不覆盖 `quote`**。它把结算值单独记在 `settled_total_minor`，
  状态置为 `disputed`，并返回一条 `Break`。`book_value()` 返回的永远是估计。
  这是本批次唯一真正重要的接口。
- **费率必须声明「基数」**。增值税是对**服务费**计征，不是对支付金额；
  第一版把所有费率都按支付金额算，于是 100 元的交易算出 20 元税，
  实际应该是 0.06 元——**三个数量级的错**。新增 `basis` 字段与 `FEE_TAX_ON_PAYMENT` 规则，
  参考实现改成两遍计算（先按支付金额，再按服务费）。
- **舍入规则是契约不是实现细节**。`apply_percentage()` 从模型里读 `half_up`/`half_even`/`down`，
  三种都实现且有测试；余数归属写在模型里而不是靠「谁先算谁拿」。
- **分账四方之和精确等于总额**，`split()` 会把余数给声明的所有者并断言总和。
- **跨币种必须有完整汇率记录**（`rate`/`quoted_at`/`source`），否则拒绝换算——
  隐式换算会把汇率损益藏进费用里。
- **计量按支付 ID 幂等**，且 `recompute()` 能从原始支付重新推导出同一个总额。

## 4. 错误语义

`FEE_UNREADABLE`、`FEE_SHAPE`、`FEE_VERSION_FIELD`、`FEE_PRINCIPLE`、`FEE_CATEGORY_UNKNOWN`、
`FEE_CATEGORY_DUPLICATE`、`FEE_CATEGORY_UNSTATED`、`FEE_CATEGORY_NOTES`、
`FEE_CATEGORY_MISSING`、`FEE_TAX_AS_REVENUE`、`FEE_TAX_NOT_REMITTED`、`FEE_COST_AS_REVENUE`、
`FEE_INTERNAL_COST_CHARGED`、`FEE_ROUNDING_UNDECLARED`、`FEE_ROUNDING_UNIT`、
`FEE_ROUNDING_NOTES`、`FEE_NO_SCHEDULES`、`FEE_SCHEDULE_ID`、`FEE_SCHEDULE_DUPLICATE`、
`FEE_BASIS_UNKNOWN`、`FEE_TAX_ON_PAYMENT`、`FEE_PROVIDER_UNKNOWN`、`FEE_CURRENCY_UNKNOWN`、
`FEE_SCHEDULE_UNREACHABLE`、`FEE_PERCENTAGE_RANGE`、`FEE_FIXED_NOT_INTEGER`、
`FEE_SCHEDULE_FREE`、`FEE_BOUND_NOT_INTEGER`、`FEE_BOUNDS_INVERTED`、`FEE_UNCAPPED_PERCENT`、
`FEE_SCHEDULE_NOTES`、`FEE_PROVIDER_NO_COST`、`FEE_BOOK_IS_TRUTH`、
`FEE_NO_AUTHORITATIVE_SOURCE`、`FEE_MISMATCH_IGNORED`、`FEE_SILENT_OVERWRITE`、
`FEE_TOLERANCE_NONZERO`、`FEE_SETTLE_LAG_UNBOUNDED`、`FEE_SETTLEMENT_NOTES`、
`FEE_SPLIT_PARTY_MISSING`、`FEE_SPLIT_UNBALANCED`、`FEE_NO_REMAINDER_OWNER`、
`FEE_SPLIT_NOTES`、`FEE_CURRENCY_MISMATCH`、`FEE_IMPLICIT_CONVERSION`、`FEE_NO_RATE_RECORD`、
`FEE_CURRENCY_NOTES`、`FEE_METERING_KEY`、`FEE_METERING_NOT_IDEMPOTENT`、
`FEE_METERING_UNRECOMPUTABLE`、`FEE_METERING_RETENTION_SHORT`、`FEE_METERING_NOTES`、
`FEE_AUDIT_CLASS_UNKNOWN`、`FEE_AUDIT_CLASS_TOO_WEAK`、`FEE_GENERATED_MISSING`、
`FEE_GENERATED_DRIFT`、`FEE_GENERATED`。

运行期拒绝码：`AMOUNT_NOT_INTEGER`、`AMOUNT_NEGATIVE`、`CURRENCY_MISMATCH`、`NO_SCHEDULE`、
`UNKNOWN_ROUNDING`、`IMPLICIT_CONVERSION`、`INCOMPLETE_RATE_RECORD`、`SPLIT_UNBALANCED`、
`ALREADY_SETTLED`、`SETTLEMENT_OVERDUE`、`TAX_IN_REVENUE`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify fee-model --repo .
python3 scripts/render-fees.py --check
python3 scripts/fees-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 算术 | 三种舍入方式各有断言；浮点金额**被拒而不是被舍入**；负数被拒；未知舍入方式被拒 |
| 报价 | 按类别拆开；总额等于各部分之和；没有费率表的组合被拒；下限与封顶生效 |
| **税基** | 税按服务费计征；用支付金额计征会大两个数量级——两条断言同时验证 |
| 口径 | 收入只含服务费；税代收代缴；内部成本不向商户收；既是收入又代缴的类别在运行期被拒 |
| **结算** | 不一致时开对账项且**账面值不变**；一致时关闭；已结算/有争议都不能再结算；超期被拒；负数被拒 |
| 分账 | 1、999、10000、123457 四种金额下四方之和都精确等于总额 |
| 币种 | 同币种不需汇率；缺汇率被拒；汇率记录不完整被拒；完整记录可换算；费用币种必须等于支付币种 |
| 计量 | 重复投递返回 `DUPLICATE` 且只记一次；可从原始支付重算出同一总额 |
| 拒绝 | 57 条规则各有用例：税算收入、税按支付计征、成本算收入、内部成本向商户收、舍入未声明、余数无归属、服务费无封顶、费率表对应的支付不可能发生、渠道无成本口径、容差非零、静默覆盖、隐式换算、计量不幂等、审计类别降级为 `config.change`…… |
| 跨批次 | 渠道不在 B26 → `FEE_PROVIDER_UNKNOWN`；B27 不支持该组合 → `FEE_SCHEDULE_UNREACHABLE`；币种不在 B09 → `FEE_CURRENCY_UNKNOWN`；审计类别不是 `money.movement` → `FEE_AUDIT_CLASS_TOO_WEAK` |
| 失败关闭 | 模型坏到无法生成契约时 `FEE_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `fees-smoke.py` 39 项断言；负向控制新增 27 个 B29 场景，共 369 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-fees.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **门禁查出了一个「有绑定却没有成本口径」的渠道**（`apple_pay`）。
  这正是 `FEE_PROVIDER_NO_COST` 存在的理由：每一笔走它的支付都在记一个未知成本。
  已补上费率表。
- **税基错误是我自己写出来的**。第一版所有费率都按支付金额计算，
  而模型注释写着「按平台服务费计征」——注释与实现不一致，
  且实现方向让应缴税额大了两个数量级。**注释先于代码说了实话**，
  修法是给费率表加 `basis` 字段并加一条规则，而不是改注释迁就实现。
- **金额门禁还查出了一处文档措辞**（`float amount` 触发 `MONEY_FLOAT_TYPE`）。
  这是误报吗？不完全是：这条规则同时约束代码用的词，
  修法是改措辞，而不是给文件加豁免。
- **税率是写死在费率表里的一个数**。真实的税涉及税号、税收管辖地、
  B2B 反向征收、免税资格、税率变更的生效日期——**全部不在本批次**。
  `tax` 在这里只是一个「不属于收入且要上缴」的口径。
- **结算报告是一个整数**。真实的结算报告是一个文件，含手续费明细、退款、拒付、
  调整项与跨日归集；把它简化成一个总额意味着**本批次无法定位差异出在哪一项**，
  只能说「差了 N」。差异定位属于对账批次。
- **`Pricer` 没有存储也没有并发**。`meter.events` 是内存字典，幂等靠它；
  真实幂等需要持久化唯一约束——与 B26/B28 同源的缺口。
- **佣金（分销/代理商分成）没有建模**。`split` 只有四方，
  真实平台还有 ISV、代理商、多级分销，且他们的分成往往按**服务费**再分一次。
- **没有生效日期与版本**。改一次费率就地生效，历史交易用哪版费率算无从谈起——
  这与 B28 给路由配置做的版本化是同一个问题，但本批次没有做。

## 9. 数据迁移

无。真实落地时需要把现有合同费率导入费率表并补上生效日期，属于实现批次。

## 10. 证据与审查

`evidence/B29/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B28 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **结算报告到达** | 覆盖账面值 → 「我们以为收多少」永远查不出来 | 账面值是估计且不可覆盖；差异开对账项；容差为零 |
| 报税 | 税混进收入 → 虚增收入且少缴 | `FEE_TAX_AS_REVENUE` + 运行期 `TAX_IN_REVENUE` |
| 计算增值税 | 按支付金额计征 → 应缴额大两个数量级 | `basis` 字段 + `FEE_TAX_ON_PAYMENT` + 两遍计算 |
| 百分比费率 + 大额交易 | 无封顶的百分比费 → 一个没人同意过的数字 | `FEE_UNCAPPED_PERCENT` |
| 分账 | 四舍五入后差一分 → 对账系统里最难查的差异 | 各部分之和必须等于总额；余数有明确归属 |
| 跨币种收费 | 隐式换算把汇率损益藏进费用 | 必须有完整汇率记录，否则拒绝换算 |
| 渠道重发计量事件 | 重复计费 | 按支付 ID 幂等；重复计数被单独保留 |
