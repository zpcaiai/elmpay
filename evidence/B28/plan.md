# B28 plan — 路由规则、灰度与配置版本

Batch: 路由规则、灰度与配置版本 · Wave W03 · Skill `pay-routing-pricing` · depends_on: [B26]

## 1. 范围

批次目标是「确定性优先级、成本/成功率/风险路由、配置审计、回滚和模拟评估」。
其中**确定性**不是五个特性之一，而是其余四个的前提：
路由决定唯一会被追问的时刻是事后——在争议里、在对账差异面前——那时配置早已改过。
如果同一笔支付在同一版本下可能得出两个结果，「这笔钱当初为什么走了 A」就永远没有答案。

1. `governance/routing-policy.json`：配置版本、确定性、6 条规则、三因子打分、
   灰度、回滚、影子评估、重试。
2. `tools/paygov/routing.py`：路由门禁（67 条规则码），含四条跨批次校验——
   目标渠道必须在 B26 有绑定、**必须在 B27 能力矩阵中确实支持该 方式/地区/币种**、
   生效权限必须在 B19 是双人控制、审计类别必须在 B23 存在。
3. `libs/routing/reference/router.py`：**可执行、可重放的路由器**（整数打分，不读时钟，不用随机数）。
4. `tools/paygov/routinggen.py` + `scripts/render-routing.py`。
5. `scripts/routing-smoke.py`：39 项运行期断言。
6. `tools/tests/test_b28_routing.py`：127 个用例。
7. `tools/negative/b28.py`：28 个负向控制场景。

## 2. 受影响组件

`governance/{routing-policy,ssot-registry}.json`、`tools/paygov/{routing,routinggen}.py`、
`libs/routing/`、`scripts/{render-routing,routing-smoke}.py`、
`contracts/routing/policy.json`、`docs/routing/ROUTING_POLICY.md`、
`tools/tests/test_b28_routing.py`、`tools/negative/b28.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **决定必须带版本号**。`Decision` 里有 `config_version` 与 `reasons`，
  `replay()` 拿着旧决定重跑它自己那个版本——这是本批次唯一真正重要的接口。
- **打分用整数基点，不用浮点**。这条是 B09 的金额门禁先查出来的（见 §8），
  但它的理由比那条规则更强：浮点加权和在两台机器上可能给出不同的排序，
  那正好摧毁本批次赖以成立的确定性。
- **探索下限**：`allocation()` 让任何有能力的候选都不低于 5%。
  纯粹「路由到成功率最高的那个」是自我强化的——拿不到流量的渠道
  永远凑不出证明自己已恢复的样本，于是一个下午的抖动被固化成一条永久死掉的通道。
- **灰度按支付意图的稳定哈希分流**。同一笔支付的重试必须落在同一分支；
  随机分流会让重试换分支 → 换渠道 → 第一次的终态还没到就发了第二次。
- **上线双人、回滚零人**。这两个方向的风险不对称：
  给回滚加审批，等于把故障时长写进流程。同理，自动放量关闭、自动回滚打开。
- **影子评估读生产配置但不能动钱**。`execute(shadow=True)` 直接抛异常。

## 4. 错误语义

`ROUTE_UNREADABLE`、`ROUTE_SHAPE`、`ROUTE_VERSION_FIELD`、`ROUTE_PRINCIPLE`、
`ROUTE_VERSION_MUTABLE`、`ROUTE_DECISION_UNVERSIONED`、`ROUTE_ACTIVATION_UNAPPROVED`、
`ROUTE_ACTIVATION_SINGLE_PERSON`、`ROUTE_HISTORY_TOO_SHORT`、`ROUTE_PERMISSION_UNKNOWN`、
`ROUTE_VERSION_NOTES`、`ROUTE_NONDETERMINISTIC`、`ROUTE_UNREPLAYABLE`、`ROUTE_NO_TIE_BREAK`、
`ROUTE_DETERMINISM_NOTES`、`ROUTE_NO_RULES`、`ROUTE_RULE_ID`、`ROUTE_RULE_DUPLICATE`、
`ROUTE_NO_PRIORITY`、`ROUTE_PRIORITY_COLLISION`、`ROUTE_RULE_NO_MATCH`、
`ROUTE_REGION_UNKNOWN`、`ROUTE_METHOD_UNKNOWN`、`ROUTE_RULE_NO_CURRENCY`、
`ROUTE_NO_AMOUNT_CEILING`、`ROUTE_RULE_NO_TARGET`、`ROUTE_TARGET_DUPLICATE`、
`ROUTE_PROVIDER_UNKNOWN`、`ROUTE_TARGET_INCAPABLE`、`ROUTE_RULE_NOTES`、`ROUTE_NO_FACTORS`、
`ROUTE_FACTOR_UNKNOWN`、`ROUTE_FACTOR_DUPLICATE`、`ROUTE_FACTOR_WEIGHT`、
`ROUTE_FACTOR_NOTES`、`ROUTE_WEIGHTS_UNNORMALISED`、`ROUTE_WINDOW_UNBOUNDED`、
`ROUTE_SAMPLE_TOO_SMALL`、`ROUTE_NO_EXPLORATION`、`ROUTE_EXPLORATION_EXCESSIVE`、
`ROUTE_SCORING_NOTES`、`ROUTE_RANDOM_SPLIT`、`ROUTE_SPLIT_KEY`、`ROUTE_CANARY_UNBOUNDED`、
`ROUTE_CANARY_UNOBSERVED`、`ROUTE_AUTO_PROMOTE`、`ROUTE_NO_AUTO_ROLLBACK`、
`ROUTE_ROLLBACK_THRESHOLD`、`ROUTE_CANARY_NOTES`、`ROUTE_ROLLBACK_IS_A_RELEASE`、
`ROUTE_ROLLBACK_GATED`、`ROUTE_ROLLBACK_SLOW`、`ROUTE_ROLLBACK_NOTES`、
`ROUTE_NO_SIMULATION`、`ROUTE_SHADOW_MOVES_MONEY`、`ROUTE_SIMULATION_DETACHED`、
`ROUTE_SIMULATION_UNCOMPARED`、`ROUTE_SIMULATION_NOTES`、`ROUTE_RETRY_NEW_KEY`、
`ROUTE_RETRY_CHANGES_PROVIDER`、`ROUTE_RETRY_UNBOUNDED`、`ROUTE_RETRY_NO_BACKOFF`、
`ROUTE_RETRY_NOTES`、`ROUTE_AUDIT_CLASS_UNKNOWN`、`ROUTE_GENERATED_MISSING`、
`ROUTE_GENERATED_DRIFT`、`ROUTE_GENERATED`。

运行期拒绝码：`UNROUTABLE`、`UNKNOWN_VERSION`、`VERSION_IMMUTABLE`、`NOT_APPROVED`、
`SELF_APPROVAL`、`NO_PREVIOUS_VERSION`、`AMOUNT_ABOVE_CEILING`、`SHADOW_CANNOT_MOVE_MONEY`、
`RETRY_KEY_CHANGED`、`RETRY_PROVIDER_CHANGED`、`RETRIES_EXHAUSTED`、`CANARY_TOO_LARGE`、
`UNKNOWN_SPLIT_KEY`、`SCORE_NOT_INTEGER`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify routing-policy --repo .
python3 scripts/render-routing.py --check
python3 scripts/routing-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| **确定性** | 同输入同决定；决定带版本号与理由；旧决定可重放；未知版本拒绝；无匹配规则拒绝而不是随便挑；并列按渠道 ID 而不是随机 |
| 版本 | 同名版本不能重发；生效需两名批准人且发布者不能是批准人；未知版本不能生效 |
| **回滚** | 切回上一个已有版本、不需要审批；没有上一个版本时拒绝 |
| **探索下限** | 落后渠道保有 5%；成功率为零也不会被饿死；单候选不拆分；样本不足不认可成功率 |
| 打分 | 三因子加权；未知渠道得 0；**浮点分数被拒**（`SCORE_NOT_INTEGER`） |
| **灰度** | 同一笔支付永远同一分支；重试不换分支；确实有分流；超上限拒绝；不支持的分流键拒绝 |
| 影子 | 能算出决定；`shadow=True` 时不能发送；正式执行可以 |
| 重试 | 换幂等键不是重试；换渠道不是重试；次数上限；退避递增 |
| 拒绝 | 67 条规则各有用例：默认可随机、决定不记版本、版本可改、单人生效、保留版本太少、优先级重复、目标渠道无能力、探索下限为零、随机分流、按用户分流、自动放量、回滚要审批、影子能动钱、重试可换渠道…… |
| 跨批次 | 目标不在 B26 → `ROUTE_PROVIDER_UNKNOWN`；B27 不支持该组合 → `ROUTE_TARGET_INCAPABLE`；B19 撤掉 `config.write` 双人 → `ROUTE_ACTIVATION_SINGLE_PERSON`；审计类别不在 B23 → `ROUTE_AUDIT_CLASS_UNKNOWN` |
| 失败关闭 | 模型坏到无法生成契约时 `ROUTE_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `routing-smoke.py` 39 项断言；负向控制新增 28 个 B28 场景，共 342 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-routing.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **金额门禁查出了我自己写的浮点打分**。第一版 `score()` 用 `float` 累加，
  被 B09 的 `MONEY_FLOAT_LITERAL` 命中。改成整数基点不是为了迁就规则——
  **浮点加权和在不同机器上可能给出不同排序，那正好摧毁本批次的确定性**。
  这是一次「规则比作者更懂作者的意图」的例子。
- **打分输入是外部给的快照，本批次不产生它**。成功率、成本、风险从哪来、
  怎么聚合、窗口如何滑动、乱序数据如何处理——**全部不在本批次**，属于后续的指标批次。
  这意味着「探索下限」保护的是分配，不是统计本身：一个坏的统计管道仍然能骗过它。
- **`allocation()` 只是比例，不是调度器**。它不知道并发、不知道容量、不做令牌桶；
  真正把 5% 流量送出去需要一个一致的分配器，本批次没有。
- **灰度只有两分支**。没有多臂、没有分层实验、没有互斥实验组管理。
- **自动回滚只声明了阈值,没有建模「多久算一个窗口」与「多少样本才触发」**——
  一个阈值 2% 的自动回滚在前 10 笔里有 1 笔失败就会触发，这是**已知的误触发面**，
  需要与指标批次一起补最小样本，本批次没有。
- **规则匹配是精确匹配三元组**，没有通配、没有区间、没有优先级继承。
  真实平台需要「EU 所有卡」这类模式，一旦引入，`ROUTE_PRIORITY_COLLISION`
  就不足以保证唯一命中，需要更强的重叠检测。
- **成本因子是一个 0–10000 的数**，没有建模阶梯费率、保底、返点，
  也没有和 B27 的结算延迟联动；真实的「成本」是一条曲线不是一个数。

## 9. 数据迁移

无。真实落地时需要把现有的隐式路由（代码里的 if/else）导出为第一个配置版本，属于实现批次。

## 10. 证据与审查

`evidence/B28/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B27 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **事后追问一笔支付的走向** | 决定不可复现 → 争议与对账都无法解释 | 决定记录配置版本与理由；版本不可变；`replay()` 可复现 |
| 按成功率自动择优 | 自我强化 → 一次抖动把一条通道永久判死 | 探索下限 + 饥饿保护 + 最小样本 |
| **灰度期间的重试** | 随机分流 → 重试换分支换渠道 → 重复扣款 | 按支付意图稳定哈希分流；重试复用幂等键且不换渠道 |
| 出问题时回滚 | 回滚要审批 → 故障时长被流程放大；「改回去」→ 又一次可能出错的发布 | 回滚零审批、有时限、且只能切回已有版本 |
| 用影子模式验证新策略 | 影子能动钱 → 迟早真动一次 | `shadow_moves_money=false`，参考实现直接抛异常 |
| 路由到一个不支持该组合的渠道 | 产生一笔谁也收不了的支付 | 与 B27 能力矩阵交叉校验 `ROUTE_TARGET_INCAPABLE` |
