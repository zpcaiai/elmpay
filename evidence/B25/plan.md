# B25 plan — 商户资料与 KYB 元数据

Batch: 商户资料与 KYB 元数据 · Wave W03 · Skill `pay-tenant-merchant-registry` · depends_on: [B24]

## 1. 范围

批次简述里有一句话决定了整个批次的形状：**「但不替代持牌机构核验」**。
一个平台最容易违反它的方式，是在自己的库里加一个叫 `verified` 的布尔字段，
然后由自己的代码把它设成 `true`。**一个平台能自己给自己发的状态，在争议里没有任何分量**。
所以本批次的第一条规则不是数据规则，而是诚实规则。

1. `governance/merchant-profile.json`：核验来源、3 类主体、4 种材料及其有效期、
   UBO 穿透、名单筛查、6 个经营类目（3 个禁止）、4 个经营地区、3 个风险等级、
   5 类重大变更、留存、审计类别、申诉。
2. `tools/paygov/merchant.py`：商户资料门禁（70 条规则码），含五条跨批次校验——
   结算币种必须在 B09 货币元数据中、`payout_account.write` 必须在 B19 是双人控制、
   留存期不得超过 B13 数据模型的最长生命周期、B24 必须仍在关闭时销毁租户 KEK、
   审计事件类别必须在 B23 中存在。
3. `libs/merchant/reference/profile.py`：**可执行的进件与 KYB 模型**（时间是调用方传入的天数，
   不读时钟，因此每一条有效期断言都可复现）。
4. `tools/paygov/merchantgen.py` + `scripts/render-merchant.py`。
5. `scripts/merchant-smoke.py`：38 项运行期断言。
6. `tools/tests/test_b25_merchant.py`：151 个用例。
7. `tools/negative/b25.py`：22 个负向控制场景。

## 2. 受影响组件

`governance/{merchant-profile,ssot-registry}.json`、`tools/paygov/{merchant,merchantgen}.py`、
`libs/merchant/`、`scripts/{render-merchant,merchant-smoke}.py`、
`contracts/merchant/profile-model.json`、`docs/merchant/MERCHANT_PROFILE.md`、
`tools/tests/test_b25_merchant.py`、`tools/negative/b25.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **核验状态必须引用外部机构**。`verification.authority_fields` 强制
  机构、决定编号、决定日期、有效期四项俱全，且有效期上限 730 天。
  参考实现里 `mark_verified()` 这个方法**存在但永远抛异常**——它是那条捷径的墓碑。
- **KYB 是持续状态，不是签约时的一次性事件**。每份材料都有有效期，
  且**收款账户证明的有效期必须最短**（180 天）：它是钱的去向，也是接管商户后第一个被改的东西。
- **命中名单既不自动放行，也不自动拒绝**。自动放行显然错；自动拒绝更隐蔽地错——
  名单按姓名匹配，误伤规模远大于命中规模，代价落在无辜的人身上。命中只能转人工。
- **改收款账户暂停结算，但不停止收款**。这是本批次最反直觉的一条，也是与 B24
  「停用不等于断电」同源的判断：把整个商户冻结，会让**已经付过钱、货还没发**的付款人
  两头落空；只冻结出款腿，钱留在平台上，等新账户被外部机构重新核验。
  因此 `apply_change()` **不会**把状态改回 `pending_review`——外部机构关于「这家公司是谁」
  的决定没有过期也没有被撤回，未经证实的是这次变更本身。
- **股权要穿透**：25% 门槛、最多五层。只看第一层股东，等于让任何人用一个空壳挡住自己。

## 4. 错误语义

`MERCHANT_UNREADABLE`、`MERCHANT_SHAPE`、`MERCHANT_VERSION_FIELD`、`MERCHANT_PRINCIPLE`、
`MERCHANT_SELF_VERIFIED`、`MERCHANT_AUTHORITY_INCOMPLETE`、`MERCHANT_VERIFICATION_FOREVER`、
`MERCHANT_SELF_ATTESTED_FACT`、`MERCHANT_DOC_ID`、`MERCHANT_DOC_DUPLICATE`、
`MERCHANT_DOC_PURPOSE`、`MERCHANT_DOC_ISSUER`、`MERCHANT_DOC_PII_FLAG`、`MERCHANT_DOC_NOTES`、
`MERCHANT_DOC_NO_EXPIRY`、`MERCHANT_ACCOUNT_PROOF_STALE`、`MERCHANT_ENTITY_DUPLICATE`、
`MERCHANT_ENTITY_NO_DOCUMENTS`、`MERCHANT_ENTITY_DOC_UNKNOWN`、
`MERCHANT_ENTITY_NO_ACCOUNT_PROOF`、`MERCHANT_ENTITY_NOTES`、`MERCHANT_COMPANY_NO_UBO`、
`MERCHANT_UBO_THRESHOLD`、`MERCHANT_UBO_DEPTH`、`MERCHANT_UBO_NO_ID`、
`MERCHANT_UBO_NO_SCREENING`、`MERCHANT_SCREENING_INCOMPLETE`、`MERCHANT_SCREENING_ONCE`、
`MERCHANT_SANCTIONS_AUTO`、`MERCHANT_CATEGORY_CODE`、`MERCHANT_CATEGORY_DUPLICATE`、
`MERCHANT_CATEGORY_RISK`、`MERCHANT_CATEGORY_NOTES`、`MERCHANT_PROHIBITED_CATEGORY_ALLOWED`、
`MERCHANT_NO_PROHIBITED_LIST`、`MERCHANT_REGION_CODE`、`MERCHANT_REGION_DUPLICATE`、
`MERCHANT_REGION_NO_CURRENCY`、`MERCHANT_CURRENCY_UNKNOWN`、`MERCHANT_REGION_ENTITY_RULE`、
`MERCHANT_REGION_NOTES`、`MERCHANT_RISK_LEVEL`、`MERCHANT_RISK_NO_LIMIT`、
`MERCHANT_RISK_NO_DELAY`、`MERCHANT_RISK_NO_APPROVER`、`MERCHANT_RISK_NOTES`、
`MERCHANT_HIGH_RISK_SINGLE_APPROVER`、`MERCHANT_RISK_LIMITS_INVERTED`、
`MERCHANT_RISK_DELAY_INVERTED`、`MERCHANT_NO_CHANGE_TRIGGERS`、`MERCHANT_CHANGE_DUPLICATE`、
`MERCHANT_CHANGE_NO_REVERIFY`、`MERCHANT_CHANGE_PERMISSION_UNKNOWN`、`MERCHANT_CHANGE_NOTES`、
`MERCHANT_CHANGE_MISSING`、`MERCHANT_ACCOUNT_CHANGE_NO_HOLD`、
`MERCHANT_ACCOUNT_CHANGE_SINGLE_PERSON`、`MERCHANT_RETENTION_SHORT`、
`MERCHANT_RETENTION_BEYOND_DATA`、`MERCHANT_RETENTION_UNSHREDDABLE`、
`MERCHANT_DOCS_PLAINTEXT`、`MERCHANT_NO_MINIMISATION`、`MERCHANT_NO_APPEAL`、
`MERCHANT_DECISION_UNEXPLAINED`、`MERCHANT_APPEAL_SELF_REVIEW`、`MERCHANT_APPEAL_UNBOUNDED`、
`MERCHANT_AUDIT_CLASS_UNKNOWN`、`MERCHANT_GENERATED_MISSING`、`MERCHANT_GENERATED_DRIFT`、
`MERCHANT_GENERATED`。

运行期拒绝码：`DENY_UNKNOWN`、`DENY_SELF_VERIFIED`、`DENY_AUTHORITY_INCOMPLETE`、
`DENY_AUTHORITY_EXPIRED`、`DENY_VALIDITY_TOO_LONG`、`DENY_NOT_ATTESTABLE`、
`DENY_DOCUMENT_MISSING`、`DENY_DOCUMENT_EXPIRED`、`DENY_UBO_INCOMPLETE`、`DENY_UBO_DEPTH`、
`DENY_SCREENING_STALE`、`DENY_SCREENING_HIT`、`DENY_PROHIBITED_CATEGORY`、`DENY_CURRENCY`、
`DENY_LIMIT`、`DENY_APPROVERS`、`DENY_SELF_APPROVAL`、`DENY_PERMISSION`、
`DENY_SETTLEMENT_HELD`、`DENY_REVERIFICATION_REQUIRED`、`DENY_NO_REASONS`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify merchant-profile --repo .
python3 scripts/render-merchant.py --check
python3 scripts/merchant-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 进件 → 材料齐全 → 提交复核 → 引用外部机构决定 → 已核验 → 收款 → 结算 |
| **不能自证** | `mark_verified()` 永远抛 `DENY_SELF_VERIFIED`；无机构决定、机构记录缺字段、有效期超上限、机构决定已过期，四种都被拒 |
| 材料 | 收款账户证明过期即视为缺失；缺失与过期分别报告；未知材料被拒；材料不齐不能提交复核 |
| **股权** | 超过穿透层数被拒；无人达到 25% 门槛被拒；实际控制人无身份证件被拒；个人收款不需要股权结构 |
| 筛查 | 从未筛查、筛查过期、命中，三种都拒；命中转 `manual_review` 而不是自动拒绝；干净的重筛不改变状态 |
| **接管** | 改收款账户 → 挂起重新核验 + 暂停结算 + **仍可收款**；发起人不能自己解除暂停；未重新核验前他人也不能；重新核验后恢复；`ubo_change` 挂起复核但不暂停结算 |
| 决策 | 决定人不能是自己的批准人；高风险一人不够、两人可通过；拒绝必须给理由；原判人不能复核自己的拒绝 |
| 资金 | 单笔与当日限额；跨日重置；地区不支持的币种不能结算；机构决定过期后停止结算；未核验不能收款 |
| 拒绝 | 70 条规则各有用例：平台自称持牌、核验不需要机构、材料无有效期、账户证明比别的活得久、公司不申报 UBO、穿透一层、命中自动放行、只筛一次、禁止类目仍放行、币种不在货币元数据、高风险限额更高、高风险一人批准、改账户不暂停结算、留存不足五年、留存超过数据模型寿命、不可申诉、审计类别不存在…… |
| 跨批次 | 币种不在 B09 → `MERCHANT_CURRENCY_UNKNOWN`；B19 撤掉 `payout_account.write` 双人控制 → `MERCHANT_ACCOUNT_CHANGE_SINGLE_PERSON`；B24 不再销毁 KEK → `MERCHANT_RETENTION_UNSHREDDABLE`；审计类别不在 B23 → `MERCHANT_AUDIT_CLASS_UNKNOWN` |
| 失败关闭 | 模型坏到无法生成契约时 `MERCHANT_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `merchant-smoke.py` 38 项断言；负向控制新增 22 个 B25 场景，共 262 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-merchant.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **本批次不做任何真实核验**。没有对接任何登记机关、名单服务或银行账户验证接口；
  `Authority` 是一个由调用方提供的数据结构，**平台只负责拒绝没有它的状态**。
  真正的接口对接、供应商选择与降级策略属于实现批次。
- **名单筛查是一个布尔字段**。参考实现里 `screening_hit` 由调用方给出，
  本批次不实现任何匹配算法，也**不建模误报率、别名、音译与模糊匹配阈值**——
  而这些恰恰是决定「转人工」这条路会不会被淹没的东西。
- **风险等级是静态标签**。没有行为评分、没有随交易历史升降级、没有回溯重定级；
  `risk` 在参考实现里是注册时传入并且不再改变的字符串。
- **限额是计数器不是限流器**。`daily_used` 按 (商户, 天) 累计，没有时区、没有并发一致性、
  没有跨节点视图——与 B24 的配额同源的简化。
- **申诉只建模了「谁不能复核」和「多少天内答复」**。申诉的证据补交、二次拒绝、
  以及**监管机构介入**都没有建模。
- **重大变更清单的完整性无人守护**。规则强制「清单里的每一项都要重新核验」，
  但没有任何规则能证明清单本身没漏掉一种变更——与 B22 §8、B24 §8 同源的缺口。
- **`payout_account_change` 之后仍可收款是一个有意的取舍**，不是无风险的结论：
  它把「付款人拿不回钱」的风险换成了「平台在可能被接管的商户上继续累积余额」。
  之所以选它，是因为余额留在平台上是可逆的，而已付款却拿不到货是不可逆的。
  真实业务需要为这段窗口设置一个**上限**（金额或天数），本批次没有建模这个上限。

## 9. 数据迁移

无。真实落地时需要为现有商户回填主体类型、材料有效期与风险等级，属于实现批次。

## 10. 证据与审查

`evidence/B25/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B24 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **平台记录商户核验状态** | 自己给自己发「已核验」，出事时无法向监管或付款人解释谁核验的 | `MERCHANT_SELF_VERIFIED` + `authority_fields` 四项俱全 + 有效期上限；参考实现的 `mark_verified()` 永远抛异常 |
| **商户被接管** | 改收款账户后第一笔结算打给攻击者 | `MERCHANT_ACCOUNT_CHANGE_NO_HOLD` 强制暂停结算；`payout_account.write` 在 B19 必须双人控制；发起人不能自己解除暂停 |
| 冻结可疑商户 | 整户冻结 → 已付款、未发货的付款人两头落空 | 只冻结出款腿：`apply_change()` 不改变核验状态，`accept_payment()` 继续放行 |
| KYB 只在签约时做一次 | 执照被吊销、证件过期、股东换人，平台一无所知 | 每份材料有有效期，收款账户证明最短；筛查有重筛周期；五类重大变更重新开启核验 |
| 名单命中自动处理 | 自动放行 → 制裁违规；自动拒绝 → 大量同名误伤 | `MERCHANT_SANCTIONS_AUTO` 两侧都挡：不得自动放行，且必须转人工 |
| 留存 KYB 材料五年 | 保留期越长，泄露面越大；租户注销后仍可读 | 材料加密存储 + 最小化收集 + 留存不得超过 B13 数据模型寿命 + B24 关闭时仍必须销毁 KEK |
