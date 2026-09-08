# B35 — 支付方式抽象与令牌引用

## 1. 这一批为什么存在

批次目标写的是：只保存 PSP/钱包令牌与非敏感指纹，禁止 PAN、CVV、磁道、完整 Apple Pay 明文令牌。
这句话没人反对，问题在它下面一层——**「什么算敏感」这份清单，仓库里存在几份。**

进入本批次时它存在四份，在三种语言里：

| 位置 | 它盯的名字 |
| --- | --- |
| `SensitiveDataGuard.DENIED_KEYS`（Java） | `pan`, `card_number`, `cvv`, `cvc`, `cid`, `track1`, `track2`, `pin`, `private_key`, `api_key`, `authorization`, `apple_pay_token`, `paymentdata` |
| `libs/audit/reference/chain.py` 的 `NEVER_LOGGED` | `card_pan`, `card_cvv`, `password`, `authorization_header` |
| `apps/checkout-web/src/provider-sdk-policy.mjs` | 正则 `secret\|private\|password\|credential\|token\|pan\|cvv\|cvc\|authorization` |
| `services/.../JdbcCommerceService.java` | 一句 `result.toLowerCase().contains("cvv")` |

**没有任何两份是相同的，也没有任何东西比对它们。** 最直接的后果就摆在前两行：
Java 守卫盯 `pan`，审计参考实现盯 `card_pan`——同一个字段换个写法就从其中一层穿过去了，
而每一层从自己的位置看都是完整的。这不是谁写错了，是没有人负责让四份保持一致，
因为「保持一致」这件事在代码里根本没有位置。

所以本批次的承重规则不是「禁止存 PAN」，是
**`PMETHOD_HARDCODED_LIST`：禁止字段清单必须是治理数据，每个实现从它派生；
硬编码的第二份必然漂移——而它已经漂了。**

## 2. 范围

**做**：平台可以持有什么（令牌引用、指纹、品牌、后四位、有效期）、绝对不能持有什么、
比对前如何规范化名字、令牌引用的形态、指纹的密码学与租户约束、可展示字段的允许清单、
保留期与审计绑定，以及**把这份清单投影到每种语言**。

**不做**：卡数据在渠道侧的处理与 PCI 范围界定（B104）、密钥本身的生命周期（B20，本批次只引用它）、
风控用的设备与行为信号（B81）。

## 3. 交付物

| 文件 | 作用 |
| --- | --- |
| `governance/payment-method.json` | 事实源：6 个禁止族 / 52 个名字、规范化规则、保管、令牌、指纹、展示、保留、租户、审计 |
| `tools/paygov/paymethodgen.py` | 由事实源派生两个投影 |
| `contracts/payment-method/sensitive-fields.json` | 生成物：语言中立清单，供 JS/Python/Go |
| `libs/security/.../SensitiveFieldCatalog.java` | 生成物：Java 常量 + `normalize()` + `denied()` |
| `scripts/render-paymethod.py` | 渲染 / `--check` 漂移检查 |
| `tools/paygov/paymethod.py` | 验证器 `payment-method`，20 条 `PMETHOD_*` 规则 |
| `SensitiveDataGuard.java` | 删掉字面量清单，改用生成目录 |
| `PaymentMethodReference.java` | scheme 允许清单改用生成目录 |
| `libs/audit/reference/chain.py` | `NEVER_LOGGED` 由契约派生，比对前规范化 |
| `tools/tests/test_b35_paymethod.py` | 单元测试，含负向控制夹具够不到的两条规则 |
| `tools/negative/b35.py` | 29 个负向控制场景 |
| `scripts/paymethod-smoke.py` | 运行期证明：四份旧清单的每个名字现在都被抓 |

## 4. 三个刻意的设计决定

### 4.1 规范化是这条规则的全部重点

`card_pan` 与 `pan` 是两个字符串，是同一个字段。不先规范化就比对，
四份清单永远会以「谁多写了一个前缀」的形式互相漏掉对方。
所以模型里 `normalization` 是受门禁保护的一等公民：小写、去掉 `_ - . 空格`，
`PMETHOD_NORMALIZATION_WEAK` 守着它。

### 4.2 投影两份，而不是让 Java 运行时读文件

Java 侧生成常量而不是启动时解析 JSON：生产代码里不需要 JSON 解析器，
漂移由 `render-paymethod.py --check` 抓。**「改副本而不改源」会让构建变红，
而不是让某一种语言悄悄变宽松。**

### 4.3 「第二份清单」的判定阈值是 3，不是 1

`PMETHOD_HARDCODED_LIST` 在一个实现里出现 **3 个及以上**目录内的名字字面量时才触发。
定成 1 会把注释、日志文案、一次性的字段名判成违规——
**一条会误报的规则只会教人绕开它**，这是 B09 已经付过学费的事。
单元测试里同时钉住了两个方向：3 个触发，2 个不触发。

## 5. 已在本地跑绿

```
python3 -m tools.paygov.cli verify payment-method --repo .  → ok:true problem_count:0
python3 -m tools.paygov.cli verify ssot --repo .            → ok:true
python3 -m unittest tools.tests.test_b23_audit             → Ran 87 tests OK
夹具基线（governance + contracts + libs-py）                → 0 problems
负向控制定向重放                                             → 前 11 个场景逐条触发预期码
```

合并后的实测效果：

```
card_pan True   pan True   PAN True   card-pan True   CVV2 True   apple_pay_token True
amount   False
```

## 6. 已知限制（诚实声明）

1. **`JdbcCommerceService` 与收银台正则尚未改写。** 本批次把 Java 守卫、
   支付方式引用、审计参考三处接到了目录上；那两处仍是自己的判断，
   只是现在 `PMETHOD_CATALOG_UNBOUND` 已经能在它们被声明为派生实现时立刻抓住。
   把它们纳入 `derived_implementations` 属于 B85（浏览器完整性）与 B39（查询模型）的范围。
2. **指纹的密钥来源只是声明**。`key_source` 指向 B20 的密钥目录，
   真正的轮换与 HSM 绑定在 B20 收口，本批次不重复证明。
3. **规范化不处理编码变形**。全角、Unicode 同形字符不在本批次的规范化规则里；
   字段名来自我们自己的 schema，不是用户输入。真正的用户输入路径由 B85 负责。
