# B11 plan — API 规范、错误与兼容模型

Batch: API 规范、错误与兼容模型 · Wave W01 · Skill `pay-state-api-contracts` · depends_on: [B10]

## 1. 范围

支付集成事故绝大多数是**契约事故**。本批次把版本、幂等、分页、错误码、追踪头、
请求签名、弃用与向后兼容做成**可执行规则**，而不是一份 API 文档。

1. `governance/api-contract.json`：15 个操作、15 个错误码、版本/幂等/分页/追踪/金额策略。
2. `tools/paygov/api.py`：契约门禁（43 条规则），含**跨事实源一致性**检查：
   操作声明驱动的状态转移必须真实存在，且其幂等键作用域与参与者必须与 B10 状态机逐条一致。
3. `tools/paygov/apigen.py` + `scripts/render-api.py`，生成：
   - `contracts/api/openapi.json`（OpenAPI 3.1）
   - `contracts/api/errors.json`（语言中立错误目录）
   - `contracts/api/transition-vectors.json`（**补上 B10 欠下的转移一致性向量**）
   - `docs/api/API_CONTRACT.md`（评审文档）
4. `contracts/api/openapi.baseline.json`：兼容性基线快照。
5. `scripts/api-smoke.py`：29 项运行期断言，把向量逐条喂给 B10 参考解释器。
6. `tools/tests/test_b11_api.py`：80 个用例。

## 2. 受影响组件

`governance/{api-contract,ssot-registry}.json`、`tools/paygov/{api,apigen,registry}.py`、
`scripts/{render-api,api-smoke}.py`、`contracts/api/`、`docs/api/`、
`tools/tests/{test_b11_api.py,support.py}`、`scripts/negative-controls.py`（扩至 73 个场景）。
无数据库变更、无服务代码。

## 3. 领域接口与数据契约

- **版本**：路径大版本 `/v1`。同一大版本内只允许加法；破坏性变更必须开新大版本。
  旧大版本并行支持不少于 12 个月；弃用用 `Sunset` 头 + 不少于 180 天预告。
- **幂等**：所有写操作必须携带 `Idempotency-Key`，记录保留不少于 168 小时。
  同键不同体 → `idempotency_key_reuse`（409），**不是覆盖**。
  渠道回调用 `X-Payment-Event-Id`，保留 720 小时。
- **分页**：**只允许游标分页**，显式禁止 `offset/page/page_number/skip`，
  且必须声明稳定全序（`created_at,id`）。理由不是审美：在持续写入的支付数据上，
  偏移分页会漏记录也会重复记录，落到对账上就是账不平。
- **追踪**：必须携带 `traceparent`（W3C Trace Context）与 `X-Request-Id`；
  追踪与日志中不得出现凭据、卡号、完整支付令牌或不必要个人信息（NN-14）。
- **金额**：线上金额一律 `{amount_minor: int64, currency: char(3)}`，不存在小数字段（NN-05）。
- **错误**：15 个稳定错误码，每个带 HTTP 状态、是否可重试、类别、**对调用方安全的文案**与**应对建议**。
  只有 429/5xx 才允许标记为可重试。
- **签名**：渠道回调必须先验签（HMAC-SHA256）+ 时间戳容忍 300 秒 + 24 小时重放窗口（NN-08）。
- **跨事实源绑定**：操作 ↔ 状态机转移的参与者与幂等键必须一致
  （`API_TRANSITION_ACTOR`、`API_TRANSITION_KEY_MISMATCH`）。
  这让 NN-03「回跳不是凭据」在 API 层与状态机层是同一条规则的两面。

## 4. 错误语义

`API_UNREADABLE`、`API_VERSION_FIELD`、`API_SHAPE`、`API_VERSIONING`、`API_DEPRECATION`、
`API_TRACE`、`API_PAGINATION_POLICY`、`API_PAGINATION`、`API_MONEY_SHAPE`、
`API_ERROR_CODE`、`API_ERROR_DUPLICATE`、`API_ERROR_STATUS`、`API_ERROR_RETRYABLE`、
`API_ERROR_MESSAGE`、`API_ERROR_LEAK`、`API_ERROR_REMEDY`、`API_ERROR_UNKNOWN`、
`API_ERROR_UNUSED`、`API_OPERATION_ID`、`API_OPERATION_DUPLICATE`、`API_ROUTE_DUPLICATE`、
`API_PATH`、`API_SUMMARY`、`API_AUTH`、`API_MUTATION_NOT_IDEMPOTENT`、
`API_IDEMPOTENCY_RETENTION`、`API_IDEMPOTENCY_CONFLICT`、`API_READ_IDEMPOTENCY`、
`API_TRANSITION_UNKNOWN`、`API_TRANSITION_KEY_MISMATCH`、`API_TRANSITION_ACTOR`、
`API_SIGNATURE`、`API_BASELINE_MISSING`、`API_BASELINE_UNREADABLE`、`API_BASELINE_MAJOR`、
`API_BREAKING_REMOVAL`、`API_BREAKING_ROUTE`、`API_BREAKING_IDEMPOTENCY`、
`API_BREAKING_ERRORS`、`API_GENERATED_MISSING`、`API_GENERATED_DRIFT`、`API_GENERATED`。

`API_GENERATED` 是失败关闭通道：契约坏到无法生成产物时，门禁必须报告而不是抛异常。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify api-contract --repo .
python3 scripts/render-api.py --check
python3 scripts/api-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 15 个操作全部通过；9 个写操作全部要求幂等键；3 个列表接口全部游标分页且有稳定全序 |
| 重复 | 8 条 accepted 向量逐条重放，状态与历史都不变；同键不同体映射到 409 而非覆盖 |
| 超时 | `provider_timeout` 标记为可重试，且应对建议明确写「**不要**当作失败」 |
| 拒绝 | 13 条 rejected 向量逐条以声明理由被拒；43 条门禁规则各有对应的拒绝用例 |
| 兼容 | 删除操作、改路由、悄悄取消幂等要求、悄悄删掉错误码——四类破坏性变更全部被基线比对拦下 |
| 泄露 | 错误文案含卡号/凭据关键词即 `API_ERROR_LEAK` |
| 失败关闭 | 契约坏到无法生成产物时给出 `API_GENERATED` 而非崩溃 |
| 运行期 | `api-smoke.py` 29 项断言；负向控制新增 8 个 B11 场景，共 73 个场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-api.py`。
**注意**：`contracts/api/openapi.baseline.json` 只有在开新大版本时才允许重录
（`scripts/render-api.py --record-baseline`）。用重录基线来"修复"破坏性变更等于取消这道门。

## 8. 已知限制（诚实声明）

- **没有生成 Java 记录**。B08 的计划里写过「Java 记录与 API schema 在 B11 随契约一起生成」，
  本批次**只兑现了 schema，没有兑现 Java 记录**。理由：本环境没有 Maven 仓库也没有编译器，
  产出一份从未被编译过的 Java 源码，等于新增一大片零验证的产物，
  它看起来像交付，实际上什么也没证明。Java 记录生成推迟到有构建环境的批次，
  届时"生成的记录能编译且能通过 `contracts/api/transition-vectors.json`"才是可验证的主张。
  这条缺口沿用剩余风险 `RR-02`，并在此明确记录，避免它变成静默漂移。
- **没有运行中的 HTTP 服务**：本批次校验的是契约与生成物，不是一个真实端点的行为。
  真实的幂等存储、唯一约束与并发测试属于 **B12**；限流与配额属于 B86–B88。
- **错误文案的泄露检查是关键词匹配**，不是语义分析。它挡得住「卡号 4111…」这种直接回显，
  挡不住把敏感信息塞进 `remedy` 或结构化字段里的写法。真正的日志脱敏属于 B23/B105。
- **兼容性基线只覆盖路由、错误码集合与幂等要求**，不覆盖请求/响应字段级别的收窄
  （删字段、枚举变窄、必填变严）。字段级契约需要完整的 schema 模型，
  应当在 API schema 真正被服务实现消费时（B12+）补上。**这是已知缺口，不是已完成。**
- 未建模：限流配额与 `Retry-After` 的具体数值、租户级 API 密钥轮换、
  Webhook 出站重试策略（属于 B37/B40+）。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B11/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B10 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| API 成为外部可达的攻击面 | 攻击者调用商户接口把支付推进成功状态（AC-01、NN-03） | `API_TRANSITION_ACTOR`：操作的调用方必须与状态转移声明的参与者一致；负向控制场景「merchant endpoint wired to a provider-only transition」 |
| 客户端会重试超时请求 | 一次超时变成两次扣款（CTRL-003、NN-04） | 所有写操作强制幂等键 + 最短保留期 + 同键不同体冲突；幂等作用域必须与状态机声明一致；8 条向量逐条验证重放无副作用 |
| 渠道回调可被伪造或重放 | 伪造回调直接写成功状态（NN-08） | 回调必须先验签（HMAC-SHA256）、时间戳容忍 ≤600 秒、声明重放窗口；`API_SIGNATURE` 四项分别可触发 |
| 错误文案会流向日志与工单 | 卡号、凭据经由错误信息扩散（NN-14） | `API_ERROR_LEAK` 关键词拦截 + 负向控制场景；OpenAPI 的 `Error` schema 关闭额外属性 |
| 契约在大版本内被悄悄收窄 | 所有集成方同时失败，且没人能证明「改之前是什么样」 | 兼容性基线快照 + 四类破坏性变更检测；基线只允许在开新大版本时重录 |
| 分页方式看起来是实现细节 | 偏移分页在持续写入下漏/重记录，最终变成对账差异 | 契约层禁止 `offset/page/skip`，操作层要求稳定全序；两处都有拒绝用例 |
