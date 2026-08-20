# B27 plan — 渠道能力与地区政策矩阵

Batch: 渠道能力与地区政策矩阵 · Wave W03 · Skill `pay-provider-account-capabilities` · depends_on: [B26]

## 1. 范围

批次目标是「表达支付方式、币种、地区、设备、授权捕获、退款、订阅、争议和可用性限制」。
表达本身不难，难的是**默认值**：一个「没写就先发出去试试」的矩阵没有限制任何东西，
它只是把拒绝推迟到付款人已经输完卡号之后，而且拒绝理由是一串我们读不懂的第三方错误码。
因此本批次的第一条规则是 `CAP_IMPLICIT_ALLOW`：**未声明即不支持**。

1. `governance/provider-capabilities.json`：解析规则、5 种支付方式、5 类设备、
   6 行能力矩阵、授权/退款/争议三套时间规则、5 行可用性、4 条地区政策。
2. `tools/paygov/capabilities.py`：能力矩阵门禁（60 条规则码），含四条跨批次校验——
   渠道必须在 B26 绑定模型中、**可收款币种必须是 B26 声明的可结算币种**、
   地区必须是 B25 的经营地区、币种必须在 B09 货币元数据中、审计类别必须在 B23 存在。
3. `libs/capability/reference/matrix.py`：**可执行的解析器**，五个维度逐个判定，
   拒绝时说明是哪一维失败。
4. `tools/paygov/capabilitiesgen.py` + `scripts/render-capabilities.py`。
5. `scripts/capabilities-smoke.py`：43 项运行期断言。
6. `tools/tests/test_b27_capabilities.py`：126 个用例。
7. `tools/negative/b27.py`：25 个负向控制场景。

## 2. 受影响组件

`governance/{provider-capabilities,ssot-registry}.json`、
`tools/paygov/{capabilities,capabilitiesgen}.py`、`libs/capability/`、
`scripts/{render-capabilities,capabilities-smoke}.py`、
`contracts/provider/capability-matrix.json`、`docs/provider/PROVIDER_CAPABILITIES.md`、
`tools/tests/test_b27_capabilities.py`、`tools/negative/b27.py`。

**修改了 B26 的产物**：`governance/provider-accounts.json` 为 `wechat` 与 `alipay`
补上了 `HKD` 结算币种。原因见 §8 第一条——这是本批次的门禁查出来的真实不一致，
因此 B26 已按依赖序重新签发证据。

## 3. 领域接口与数据契约

- **解析顺序是契约的一部分**：地区 → 支付方式 → 渠道对 → 地区命中 → 币种 → 设备。
  任一步不命中即拒绝，且拒绝码指出是哪一维——`DEVICE_UNSUPPORTED` 与
  `CURRENCY_UNSUPPORTED` 对前端是两种完全不同的提示。
- **设备是硬限制不是提示**：Android 上没有 Apple Pay，把它显示出来只会得到一个死按钮。
- **授权不是「预留了一笔钱」**，而是「发卡行答应在若干天内认这笔账」。
  过期后捕获在真实收单机构**可能仍然成功**，参考实现依然拒绝——
  因为持卡人有权拒付，而举证责任在我们。PayPal 的保证期只有 72 小时，
  和卡的 168 小时写在同一个常量里，就是「延迟发货订单收不到钱」的标准答案。
- **退款窗口关闭后不能再显示退款按钮**。一个点了不生效的按钮比没有按钮更糟：
  客服和商户都会以为钱已经在路上。
- **争议的时钟不是我们的**。`deadline_is_external=true` 是为了防止有人把它当 SLA 去「优化」。

## 4. 错误语义

`CAP_UNREADABLE`、`CAP_SHAPE`、`CAP_VERSION_FIELD`、`CAP_PRINCIPLE`、`CAP_IMPLICIT_ALLOW`、
`CAP_SILENT_FALLBACK`、`CAP_RESOLUTION_NOTES`、`CAP_METHOD_ID`、`CAP_METHOD_DUPLICATE`、
`CAP_METHOD_KIND`、`CAP_METHOD_NOTES`、`CAP_METHOD_UNKNOWN`、`CAP_DEVICE_UNKNOWN`、
`CAP_NO_MATRIX`、`CAP_PROVIDER_UNKNOWN`、`CAP_ROW_DUPLICATE`、`CAP_ROW_NO_REGION`、
`CAP_REGION_UNKNOWN`、`CAP_ROW_NO_CURRENCY`、`CAP_CURRENCY_UNKNOWN`、
`CAP_CURRENCY_UNSETTLEABLE`、`CAP_ROW_NO_DEVICE`、`CAP_AUTH_UNSTATED`、
`CAP_AUTH_NEVER_EXPIRES`、`CAP_AUTH_WINDOW_WITHOUT_AUTH`、`CAP_OVER_CAPTURE`、
`CAP_REFUND_NO_WINDOW`、`CAP_REFUND_UNSTATED`、`CAP_REFUND_ELSEWHERE`、
`CAP_DISPUTE_NO_WINDOW`、`CAP_DISPUTE_NO_DEADLINE`、`CAP_DISPUTE_DEADLINE_INVERTED`、
`CAP_SUBSCRIPTION_UNSTATED`、`CAP_ROW_NOTES`、`CAP_CAPTURE_AFTER_EXPIRY`、
`CAP_NO_REAUTHORIZATION`、`CAP_AUTH_NOTES`、`CAP_REFUND_PROMISED_BEYOND_WINDOW`、
`CAP_REFUND_NO_FALLBACK`、`CAP_OVER_REFUND`、`CAP_REFUND_NOTES`、
`CAP_DISPUTE_DEADLINE_INTERNAL`、`CAP_DISPUTE_AUTO_ACCEPT`、`CAP_DISPUTE_NO_EVIDENCE`、
`CAP_DISPUTE_NOTES`、`CAP_DEGRADED_UNDEFINED`、`CAP_MAINTENANCE_UNDECLARED`、
`CAP_AVAILABILITY_NOTES`、`CAP_AVAILABILITY_MISSING`、`CAP_REGION_DUPLICATE`、
`CAP_REGION_NO_METHOD`、`CAP_REGION_METHOD_UNSUPPORTED`、`CAP_REGION_ACQUIRER_UNSTATED`、
`CAP_SCA_UNSTATED`、`CAP_SCA_DISABLED`、`CAP_REGION_NOTES`、`CAP_AUDIT_CLASS_UNKNOWN`、
`CAP_GENERATED_MISSING`、`CAP_GENERATED_DRIFT`、`CAP_GENERATED`。

运行期拒绝码：`UNSUPPORTED`、`UNKNOWN_PROVIDER`、`UNKNOWN_METHOD`、`REGION_FORBIDS_METHOD`、
`DEVICE_UNSUPPORTED`、`CURRENCY_UNSUPPORTED`、`NO_AUTHORIZATION_STEP`、`AUTH_EXPIRED`、
`OVER_CAPTURE`、`PARTIAL_CAPTURE_UNSUPPORTED`、`ALREADY_CAPTURED`、`REFUND_WINDOW_CLOSED`、
`OVER_REFUND`、`PARTIAL_REFUND_UNSUPPORTED`、`REFUND_ELSEWHERE`、`DISPUTE_WINDOW_CLOSED`、
`DISPUTE_DEADLINE_PASSED`、`DISPUTE_EVIDENCE_INCOMPLETE`、`DISPUTE_AUTO_ACCEPT`、
`SUBSCRIPTION_UNSUPPORTED`、`PROVIDER_UNAVAILABLE`、`SILENT_FALLBACK`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify provider-capabilities --repo .
python3 scripts/render-capabilities.py --check
python3 scripts/capabilities-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 声明过的组合解析成功，返回唯一命中的那一行 |
| **未声明即拒绝** | 渠道对没声明、地区不在行内、币种没声明、设备没声明——四种拒绝码各不相同 |
| 不静默替换 | 换渠道、换支付方式、维护窗口内改道，三种都被拒 |
| **授权** | 钱包没有授权步骤；七天后过期；过期捕获被拒；超额捕获被拒；重复捕获被拒；不支持部分捕获的渠道拒绝部分捕获；过期后必须重新授权 |
| **退款** | 窗口内可退；超过捕获金额被拒；窗口关闭后按钮消失且退款被拒并给出替代路径；非原路返回被拒 |
| **争议** | 窗口外不能开；答复时限由渠道设定；材料不全不能应诉；错过时限即判负；自动认赔被拒但人工认赔可以 |
| 订阅与 SCA | 不支持订阅的组合被拒；欧盟强制 SCA、境内不强制、未知地区被拒 |
| 拒绝 | 60 条规则各有用例：默认放行、未声明也发出去、静默换渠道、授权无有效期、钱包声明授权窗口、超额捕获、退款窗口为零、非原路退款、答复时限超出争议窗口、**可收款但不可结算的币种**、地区承诺矩阵没有的方式、欧盟关掉 SCA、渠道没有可用性行、计划维护无窗口…… |
| 跨批次 | 币种不在 B26 结算列表 → `CAP_CURRENCY_UNSETTLEABLE`（**本批次真的触发了一次，见 §8**）；渠道不在 B26 → `CAP_PROVIDER_UNKNOWN`；地区不在 B25 → `CAP_REGION_UNKNOWN`；审计类别不在 B23 → `CAP_AUDIT_CLASS_UNKNOWN` |
| 失败关闭 | 模型坏到无法生成契约时 `CAP_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `capabilities-smoke.py` 43 项断言；负向控制新增 25 个 B27 场景，共 314 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-capabilities.py`。
注意 B26 的 `governance/provider-accounts.json` 也被改过（见 §2），回滚时需一并处理。

## 8. 已知限制（诚实声明）

- **门禁查出了我自己写的不一致**。B27 声称微信/支付宝可以在香港收 HKD，
  而 B26 只给它们声明了 CNY 结算——`CAP_CURRENCY_UNSETTLEABLE` 直接命中。
  两种修法：改窄 B27，或改宽 B26。**选择改宽 B26**，因为微信支付香港与 AlipayHK
  确实以 HKD 结算，改窄 B27 是用建模捷径掩盖一个真实能力。代价是 B26 重新签发证据。
- **能力矩阵是静态声明，不是渠道的真实答复**。渠道随时可能在没有通知的情况下
  收紧某个国家或某个 MCC 的支持；本批次**没有任何机制发现矩阵与现实的偏离**——
  这需要一个对账任务，属于后续批次。
- **可用性只有「计划维护」一个维度**。没有实时健康探测、没有成功率下降的自动识别、
  没有熔断——这些属于 B28 之后的路由批次。
- **争议只建模了时限与材料清单**，没有建模举证材料的质量、渠道的二次拒付（pre-arbitration）、
  以及**争议率超标导致的渠道处罚**（monitoring program），而后者才是真正会让商户被下线的东西。
- **订阅只是一个布尔值**。没有建模扣款周期、重试策略、金额变更通知、
  以及各地区对「可取消性」的法定要求。
- **矩阵行数很少（6 行）**，真实平台会有数百行；本批次没有验证
  「行数增长后解析仍然唯一」这一性质，只有 `CAP_ROW_DUPLICATE` 挡住同一对重复。
- **`refund_window_days` 与 `dispute_window_days` 是我按行业常识填的**，
  不是从渠道文档核对来的；它们的**数值**需要在实现批次逐一对齐真实文档，
  本批次保证的是**结构**（一定有窗口、一定有关闭日、答复时限一定在窗口内）。

## 9. 数据迁移

无。真实落地时需要把现有商户的可用支付方式按矩阵重新计算一次，属于实现批次。

## 10. 证据与审查

`evidence/B27/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B26 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **付款人选择支付方式** | 默认放行 → 失败发生在输完卡号之后，理由是第三方错误码 | 未声明即不支持；拒绝码指明失败的维度 |
| 渠道故障时自动改道 | 付款人以为在用 A 付款，账单上是 B，争议举证责任在我们 | `silent_fallback_*` 全部为 false；维护期拒绝而不是改道 |
| **延迟发货后捕获** | 授权已过期，捕获可能成功但可被拒付 | 授权有效期按行声明；过期捕获拒绝；必须重新授权 |
| 客服承诺「给你退款」 | 窗口已关闭，退款不会发生，钱也没回去 | 窗口关闭后不提供退款入口，并给出 `manual_or_dispute` 替代路径 |
| 争议自动认赔 | 一次「省事」变成欺诈者可反复利用的通道 | `auto_accept_allowed=false`；人工认赔仍可 |
| 收一种结不了的币 | 收得进来、结不出去，钱卡在渠道 | `CAP_CURRENCY_UNSETTLEABLE` 与 B26 交叉校验 |
| 欧盟关闭强客户认证以提升转化 | 违反 PSD2，且争议责任转移到商户 | `CAP_SCA_DISABLED` 把它写成不可配置 |
