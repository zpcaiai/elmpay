# B32 plan — Payment Intent 服务

Batch: Payment Intent 服务 · Wave W04 · Skill `pay-payment-intents-attempts` · depends_on: [B31]

## 1. 范围

W04 的第一批。目标里的五件事——不可变金额快照、过期时间、确认策略、支付方式约束、
业务订单关联——由第一件撑住：**付款人授权的是一个具体数字**。
如果那个数字事后可改，「他同意的」和「被扣的」就被允许不同，
而事后没有任何记录能说明差别在哪。**改金额不是编辑，是另一次付款。**

1. `governance/payment-intent.json`：金额快照、生命周期（引用 B10）、过期、确认、
   支付方式约束、订单关联、金额不变量、客户端引用。
2. `tools/paygov/intent.py`：意图门禁（51 条规则码），含五条跨批次校验——
   **状态/终态/成功态必须与 B10 状态机逐字一致**、快照字段必须存在于 B08 实体、
   支付方式来源必须是 B27 能力矩阵、精度来源必须是 B09 货币元数据、
   审计类别必须是 B23 的 `money.movement`。
3. `libs/intent/reference/intent.py`：**可执行的意图**（frozen dataclass 快照、
   幂等确认、调度器驱动的过期）。
4. `tools/paygov/intentgen.py` + `scripts/render-intent.py`。
5. `scripts/intent-smoke.py`：44 项运行期断言。
6. `tools/tests/test_b32_intent.py`：103 个用例。
7. `tools/negative/b32.py`：30 个负向控制场景。


## 2. 受影响组件

`governance/{payment-intent,ssot-registry}.json`、`tools/paygov/{intent,intentgen}.py`、
`libs/intent/`、`scripts/{render-intent,intent-smoke,test-summary-mp}.py`、
`contracts/payment/intent.json`、`docs/payment/PAYMENT_INTENT.md`、
`tools/tests/test_b32_intent.py`、`tools/negative/b32.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

- **`Snapshot` 是 `frozen=True` 的 dataclass**。金额不可变不是一条注释，
  而是运行期直接抛 `FrozenInstanceError`；`amend()` 再按字段名拒绝一次；
  没有「管理员可以改」的路径。三道门是有意的：可变对象上的约定不是保证（与 B30 §8 同源）。
- **状态机引用 B10 而不是重新定义**。`INTENT_STATES_DIVERGE` 双向校验：
  改这里会被发现，改 B10 也会被发现。两处各写一份状态，分叉的那天没有人会注意到。
- **过期由调度器写入终态**，不是「下一个请求顺便发现」——
  后者意味着一笔三天没人碰的意图在第四天仍然可确认。
- **确认幂等**：同键返回同结果；换一个键再确认被拒，因为那是第二次付款。
- **支付方式只能收窄不能放宽**：风控可以在确认前砍掉一种，
  但没有人可以给一笔已展示给付款人的意图加上它当时没有的方式。
- **订单只存引用**。`create()` 直接拒绝 `line_items` / `shipping_address` /
  `customer_email` 这些字段，门禁还会检查它们**没有出现在 B08 实体上**。

## 4. 错误语义

`INTENT_UNREADABLE`、`INTENT_SHAPE`、`INTENT_VERSION_FIELD`、`INTENT_PRINCIPLE`、
`INTENT_AMOUNT_MUTABLE`、`INTENT_SNAPSHOT_INCOMPLETE`、`INTENT_AMOUNT_NOT_MINOR`、
`INTENT_EXPONENT_SOURCE`、`INTENT_FIELD_UNKNOWN`、`INTENT_SNAPSHOT_NOTES`、
`INTENT_STATES_DIVERGE`、`INTENT_SUCCESS_DIVERGE`、`INTENT_LIFECYCLE_UNSOURCED`、
`INTENT_LIFECYCLE_NOTES`、`INTENT_NO_EXPIRY`、`INTENT_EXPIRY_TOO_LONG`、
`INTENT_EXPIRY_LATE`、`INTENT_EXPIRY_EXTENDABLE`、`INTENT_EXPIRED_LIVES`、
`INTENT_EXPIRY_LAZY`、`INTENT_EXPIRY_NOTES`、`INTENT_NO_IDEMPOTENCY`、
`INTENT_IDEMPOTENCY_SCOPE`、`INTENT_MULTI_SUCCESS`、`INTENT_CONCURRENT_CONFIRM`、
`INTENT_RETURN_PAGE_EVIDENCE`、`INTENT_NO_AUTHORITATIVE_SOURCE`、
`INTENT_CONFIRMATION_NOTES`、`INTENT_METHODS_UNFROZEN`、`INTENT_METHODS_WIDENED`、
`INTENT_METHODS_UNSOURCED`、`INTENT_METHOD_NOTES`、`INTENT_OWNS_ORDER`、
`INTENT_ORDER_REFERENCE`、`INTENT_ORDER_NOT_UNIQUE`、`INTENT_ORDER_CONTENT_ALLOWED`、
`INTENT_ORDER_NOTES`、`INTENT_OVER_CAPTURE`、`INTENT_OVER_REFUND`、
`INTENT_NEGATIVE_AMOUNT`、`INTENT_ZERO_AMOUNT`、`INTENT_INVARIANT_NOTES`、
`INTENT_CLIENT_SECRET_CREDENTIAL`、`INTENT_CLIENT_SECRET_BROAD`、
`INTENT_CLIENT_SECRET_ETERNAL`、`INTENT_CLIENT_SECRET_NOTES`、
`INTENT_AUDIT_CLASS_UNKNOWN`、`INTENT_AUDIT_CLASS_TOO_WEAK`、`INTENT_GENERATED_MISSING`、
`INTENT_GENERATED_DRIFT`、`INTENT_GENERATED`。

运行期拒绝码：`AMOUNT_IMMUTABLE`、`AMOUNT_NOT_INTEGER`、`AMOUNT_NOT_POSITIVE`、
`CURRENCY_UNKNOWN`、`DUPLICATE_LIVE_INTENT`、`ORDER_CONTENT_FORBIDDEN`、
`NO_IDEMPOTENCY_KEY`、`IDEMPOTENCY_KEY_REUSED`、`INTENT_EXPIRED`、`EXPIRY_NOT_EXTENDABLE`、
`EXPIRY_TOO_LONG`、`METHOD_NOT_ALLOWED`、`METHOD_WIDENED`、`ILLEGAL_TRANSITION`、
`ALREADY_TERMINAL`、`RETURN_PAGE_NOT_EVIDENCE`、`UNTRUSTED_SOURCE`、`OVER_CAPTURE`、
`OVER_REFUND`、`NOT_SCHEDULER`、`UNKNOWN_INTENT`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify payment-intent --repo .
python3 scripts/render-intent.py --check
python3 scripts/intent-smoke.py
python3 scripts/test-summary.py --out evidence/B32/test-results/summary.json
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| **金额不可变** | 直接赋值抛 `FrozenInstanceError`；`amend()` 拒绝金额与币种；正确做法是新建一笔 |
| 创建 | 浮点/布尔/零/负金额被拒；未知币种、未知方式被拒；订单内容字段逐个被拒；超长有效期被拒 |
| **订单唯一** | 同一订单第二笔在途意图被拒；原意图进入终态后可以再开 |
| 过期 | 延长有效期的方法只会抛异常；`amend()` 也改不了；过期后不能确认；只有调度器能置为过期；未到期不能置为过期 |
| 确认 | 无幂等键被拒；同键返回同结果；换键被拒；快照外的方式被拒；终态不能确认 |
| 支付方式 | 放宽被拒、收窄允许、收窄不影响金额 |
| **成功来源** | 回跳页方法只会抛异常；不可信来源的跃迁被拒；已验签事件可以授权；非法跃迁被拒 |
| 金额不变量 | 超额捕获、零捕获、超额退款被拒；正常捕获与退款通过 |
| 拒绝 | 51 条规则各有用例：金额可变、快照缺币种、第二张精度表、快照字段不在 B08、状态与 B10 分叉、成功态分叉、有效期可延长、过期仍可确认、惰性过期、无幂等键、全局幂等键、回跳页当证据、方式可放宽、平台拥有订单、订单可有两笔在途、零金额、客户端引用带凭证、审计类别降级…… |
| 跨批次 | 改 B10 状态 → `INTENT_STATES_DIVERGE`；给 B08 实体加 `customer_email` → `INTENT_ORDER_CONTENT_ALLOWED`；清空 B27 支付方式 → `INTENT_METHODS_UNSOURCED` |
| 失败关闭 | 模型坏到无法生成契约时 `INTENT_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `intent-smoke.py` 44 项断言；负向控制新增 30 个 B32 场景，共 455 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-intent.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **测试套件在 B33 撞上了执行时长上限，工具链因此被改了**。到 B32 全量套件单进程 ~42 秒，
  上限 45 秒。真正的原因不是批次多，而是**每个测试都重建一次夹具**：
  剖析显示 78% 的墙钟时间花在夹具的创建与删除上。
  修法在 B33 落地（见 `evidence/B33/plan.md` §8 与 `.ai/PROGRESS.md`）：
  夹具改为每进程一份、测试之间按快照差异还原，测试套件并行执行。
  **B32 本身没有引入新的运行器**——中途试过一个并行副本，但它无法满足
  `evidence-policy.json` 对命令类的匹配要求，而绕过那条匹配只需要在命令行加一句注释，
  那会把检查变成装饰。已回退。

- **`Intents` 没有存储也没有并发**。「并发确认串行化」在治理模型里是一个 `true`，
  参考实现用「已有其他幂等键即拒绝」近似它；真正的串行化需要数据库层的唯一约束与行锁，
  **本批次不提供**。
- **过期靠调用方传入分钟数**。没有真实时钟、没有调度器实现、没有时区；
  `expire()` 只证明「只有调度器角色能做且必须真的到期」。
- **`transition()` 的合法跃迁表是手抄 B10 的**。门禁校验了状态**集合**与终态一致，
  但**没有校验转移边**逐条一致——参考实现里的 `TRANSITIONS` 与 B10 的 `transitions`
  可能分叉而不被发现。这是本批次最实在的缺口。
- **没有建模 attempt**。一次意图下的多次尝试、失败后重试、以及 attempt 与 intent
  的金额关系属于 B33。
- **`client_secret_ref` 只是一个字符串**。真实实现需要短期签名、绑定来源、
  以及泄露后的吊销路径，本批次只声明「不含凭证、单意图、随意图过期」。
- **零金额被一刀切禁止**。真实业务里「零元验卡」是存在的（预授权 0 元校验卡有效性），
  本批次**有意不支持**：它应该走一条明确的验卡接口，而不是伪装成一笔付款。
  如果将来需要，必须新增一个显式的意图类型，而不是放开这条规则。

## 9. 数据迁移

无。真实落地时需要为既有支付记录补 `external_reference` 唯一约束，属于实现批次。

## 10. 证据与审查

`evidence/B32/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B31 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **意图创建后金额被改** | 付款人同意的与被扣的不是同一个数，且事后看不出来 | frozen 快照 + `amend()` 按名拒绝 + 无特权路径；改金额只能新建 |
| 「把有效期往后延一延」 | 用上周的价格扣今天的钱 | 有效期创建时写死、不可延长、过期不可确认 |
| 重试确认 | 同一笔支付被扣两次 | 幂等键必填、同键同结果、换键即拒 |
| **用回跳页确认支付** | 付款人自己的浏览器就能伪造成功 | 回跳页方法只会抛异常；只接受已验签事件或服务端查询 |
| 事后加一种支付方式 | 付款人看到的与最终可用的不一致 | 方式快照只能收窄 |
| 同一订单开两笔意图 | 最便宜的一种重复扣款 | 一个订单同时只有一笔在途意图 |
| 把订单内容复制进支付平台 | 出现第二个订单系统，客服相信错的那一边 | 创建时拒绝订单内容字段，并交叉校验 B08 实体上没有它们 |
