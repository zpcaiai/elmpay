# B34 — 授权、捕获、撤销与关闭

## 1. 这一批为什么存在

B34 的清单看起来是六个动作：即时捕获、延迟捕获、部分捕获、撤销、关闭、不确定结果查询。
五个已经在仓库里了。第六个 —— **关闭** —— 不在，而且它的缺席不长得像 bug。

进仓库时的实际状态：

- `PaymentStateMachine.recordCapture` 里 `CAPTURE_FINALITY_INVALID` 要求
  「终态捕获必须等于不可变的意图金额」；
- `PaymentService.voidAuthorization` 要求 `capturedAmountMinor() == 0`。

两条合起来的后果是：授权 1000、捕获 600 之后，剩下的 400 **既不能撤销也不能关闭**。
意图停在 `AUTHORIZED`，代码里没有任何一条路径去释放那 400。唯一的出口是等授权过期。

按 B27 的能力矩阵，Stripe 卡授权 `authorization_valid_hours = 168`。
也就是说：付款人的 400 被冻整整一周，而账上「这笔还可能再捕获多少」永远算不准 ——
敞口报表和对账同时失真。捕获的 600 一切正常，商户收到钱，账本平，
**错的部分不在账上**：是别人的钱，在我们手里，没有动作能还回去，也没有数字说清楚有多少。

所以本批次的承重规则是 `CAPTURE_NO_EXPLICIT_CLOSE`，第二条是 `CAPTURE_EXPIRY_AS_RELEASE`：
把过期写成释放路径不是设计决策，是把这个疏漏加上计时器之后提拔成了政策。

## 2. 范围与不做的事

**做**：授权后的资金生命周期 —— 捕获（即时/延迟/部分/多次）、撤销、关闭、以及这四者的
拒绝语义与终态映射。

**不做**：未知结果的落定语义。那是 B33 的领域（`ATTEMPT_TIMEOUT_IS_FAILURE`、
「未解决的未知挡住下一次尝试」），已由该批次的向量证明。本批次的模型里保留 `query` 操作并由
`CAPTURE_UNKNOWN_IS_SUCCESS` 守住「查询不制造成功」，但**向量里不重复 B33 的用例** ——
一份测试别人规则的向量表，测的是别人。

**不新增状态**。关闭后的部分捕获停在 `captured`，`captured_amount_minor < amount_minor`
本身就说明捕获阶段已结束、剩余已释放。这个组合**只允许由 close 产生**，
不允许由「捕获完就不管了」隐式产生。这样 B10 的 7 状态机、B08 领域模型、
SQL 的 `CHECK` 约束都不需要动 —— 一个新状态会波及十处已签发的产物，而它并不换来新的表达力。

## 3. 交付物

| 文件 | 作用 |
| --- | --- |
| `governance/capture-lifecycle.json` | 事实源：5 个操作、4 种捕获模式、5 条不变量、终态映射、一致性绑定 |
| `libs/capture/reference/capture.py` | 可执行参考实现 |
| `tools/paygov/capture.py` | 验证器 `capture-lifecycle`，20 条 `CAPTURE_*` 规则 |
| `tools/paygov/capturegen.py` + `scripts/render-capture.py` | 由模型与参考派生向量；漂移即失败 |
| `contracts/capture/vectors.json` | 12 条语言中立向量（含拒绝发生在第几步、以哪条码拒绝） |
| `PaymentStateMachine.closeAfterPartialCapture` / `voidAuthorization` | 三条释放路径收拢到状态机一处 |
| `PaymentService.closeAuthorization` | 服务层不再自判，委托状态机 |
| `CaptureLifecycleVectorsTest.java` | 对真实状态机逐条重放全部向量 |
| `tools/tests/test_b34_capture.py` | 24 个单元测试 |
| `tools/negative/b34.py` | 24 个负向控制，每个声明期望触发的规则码 |
| `scripts/capture-smoke.py` | 运行期证明（16 项断言） |

## 4. 三个刻意的设计决定

### 4.1 拒绝码是契约的一部分

参考实现与 Java 实现必须**因为同一个理由**拒绝同一个输入，不只是都拒绝。
所以 Java 侧原来的 `CAPTURE_NOT_ALLOWED` / `VOID_NOT_ALLOWED` 被拆成
`AUTH_NOT_ACTIVE` / `CAPTURE_AMOUNT_NOT_POSITIVE` / `CAPTURE_EXCEEDS_AUTHORIZED` /
`VOID_AFTER_CAPTURE` / `CLOSE_WITHOUT_CAPTURE`，与向量里的码一一对应。
一个笼统的拒绝码在凌晨三点等于没有信息。

### 4.2 三条释放路径必须在同一处判

`PaymentService` 原来自己重写了 void 的前置条件。CAP-I2 说的是「授权离开活动状态
只有三条显式路径」——一个跨两层复制的守卫，就是这两层将来会不一致的地方。
现在服务层调用 `stateMachine.voidAuthorization` / `closeAfterPartialCapture`，
判定只有一份。

### 4.3 删掉一条永远触发不了的守卫

写 close 时先加了 `CLOSE_NOTHING_TO_RELEASE`（全额捕获后无剩余可关闭）。
随后发现全额捕获会把状态推到 `captured`，`AUTH_NOT_ACTIVE` 先一步拦下，
这条永远不会触发。规则淘汰会把它标成虚设 —— 与其留着好看，不如删掉。

## 5. 已在本地跑绿

```
python3 scripts/render-capture.py --check            → up-to-date
python3 scripts/capture-smoke.py                     → checks=16 failures=0
  关键一行：without close the remaining 400 is held for up to 168h
./gradlew :services:payment-core:test --tests '*CaptureLifecycleVectorsTest*'
                                                     → BUILD SUCCESSFUL（12 条向量逐条通过）
tools/negative/b34.py 定向重放                        → 基线干净；24/24 场景各自触发预期规则码
```

## 6. 已知限制（诚实声明）

1. **没有真实渠道调用**。close 在渠道侧走的是 cancel/void 接口，本批次证明的是本地生命周期
   与状态机语义。渠道是否真的释放了那 400，要到 B40–B55 的沙箱认证才能证明，
   在那之前 `provider_certification` 门禁保持阻断。
2. **过期路径没有调度器证据**。`expiry_requires_exposure_alert` 目前是模型里的一条声明，
   真正发告警的调度与敞口报表属于 B90+ 与 B96+。
3. **能力矩阵是声明不是观测**。`partial_capture` 取自 B27 的静态矩阵。渠道单方面改能力
   不会自动反映过来 —— 这是 B27 已登记的性质，不在本批次收口。
