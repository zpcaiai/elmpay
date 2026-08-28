# ELMPay SOTA 全面测试计划

版本：2026-08-28
适用范围：`.payment-platform/skill-package` 定义的 B00–B127、当前仓库所有实现与治理工具。
可执行矩阵：[`testing/test-matrix.json`](../../testing/test-matrix.json)
编排器：[`scripts/run-test-matrix.py`](../../scripts/run-test-matrix.py)

## 1. 测试目标与边界

本计划把支付平台的功能正确性、资金安全、租户隔离、外部渠道契约、故障恢复、安全性、性能和发布控制纳入同一个可重复矩阵。矩阵由 21 个套件（18 个 local、3 个 external）组成，对 manifest 中的 128 个批次执行**恰好一次覆盖校验**；每个套件含具体步骤、预期结果、目标代码路径和可执行命令。

“矩阵完整”不等于“功能完成”，也不等于认证。当前仓库默认认证状态仍是 `0/128 NOT_CERTIFIED`。以下事项必须由独立主体在批准环境中产生并签署证据，不能由本地测试代替：

- 独立人工评审与 Git 跟踪的 `review.json`；
- Provider 官方生产认证和真实商户/渠道验收；
- 生产 Kubernetes、多地域 DR、RPO/RTO 和 failback 演练；
- PCI DSS、渗透/红队、UAT、财务/运营签署；
- 生产 shadow/canary、回滚、商户验收、SLA 与最终发布签署。

这些项目在矩阵中使用 `execution: external`，运行器报告 `BLOCKED`，不会被降级为 PASS。

## 2. 测试金字塔

| 层级 | 验证内容 | 主要入口 | 通过条件 |
| --- | --- | --- | --- |
| 治理/静态 | manifest、SSOT、需求、控制、威胁模型、生成物、模块边界 | `python3 -m tools.paygov.cli verify-all --repo .` | 退出码 0；无 dangling/漂移 |
| 单元/属性/模型 | Money、状态机、金额精度、授权、幂等、账本、风险规则 | `tools/tests`、`testing/`、Gradle tests | 失败数 0；关键测试不得跳过 |
| 契约/模拟器 | OpenAPI/AsyncAPI、Provider 请求/响应/签名/错误/超时 | connectors tests、local simulators | schema、canonicalization、错误语义一致 |
| 集成/E2E | Intent→Attempt→Auth/Capture→Webhook→Ledger→Refund/Dispute/Settlement | Gradle modules、Node SDK/web tests | 端到端状态、金额、租户和事件一致 |
| 并发/故障 | 重试、双击、多实例竞争、乱序、重复、锁丢失、时钟漂移、回调先于响应 | `testing/` fault vectors、service tests | 每个副作用最多一次；未知状态不乐观成功 |
| 安全 | SAST/DAST/IAST、secret、依赖、SBOM、供应链、滥用/钓鱼/e-skimming | governance、negative controls、外部扫描器 | 阻断级发现为 0；工具缺失 FAIL/BLOCKED |
| 性能/容量 | 基线、峰值、突发、长稳、队列/DB/Provider 降级、恢复 | `testing/test_runtime_scale.py`、压测工具 | SLO、错误预算、容量余量和恢复目标达标 |
| UAT/发布 | 业务验收、财务/运营、shadow/canary、回滚、DR、商户签署 | external evidence bundle | 独立签署、digest/commit 绑定、未过期 |

## 3. 数据、环境与隔离规则

1. 只使用合成租户、商户、订单、令牌和 Provider sandbox 数据；禁止真实卡号、生产凭证、客户 PII、线上写操作。
2. `run-test-matrix.py` 使用 `ELMPAY_TEST_MODE=1`、`ELMPAY_ENVIRONMENT=TEST`，并移除常见 secret/credential 环境变量；命令以 argv 执行，禁止 shell 拼接。
3. 本地环境验证代码、契约和治理；CI 验证固定工具链、全测试与静态/依赖/secret/SBOM；UAT/生产观察环境只允许经批准的非破坏性流量。
4. 每个结果包含 matrix digest、commit、命令、退出码、耗时和输出尾部。报告放在 `build/test-matrix/`，运行器禁止写 `evidence/`，尤其不触碰 B00 evidence。
5. 任何不确定的 Provider/网络/异步结果必须记录为 `UNKNOWN` 或 `BLOCKED`，不能转换为成功。

## 4. 覆盖模型和门禁

矩阵覆盖门禁：

- 从 skill manifest 读取 B00–B127，必须是连续 128 个 ID；
- 每个 ID 在且仅在一个 suite 的 `batch_ids` 出现；
- 所有 local suite 统一通过 `scripts/run-code-suite.py` 进入；该入口自动发现全部 `testing/test_*.py`，要求每个模块恰好归属一个 slice。新增、删除、拼写错误或重复归属都会在任何测试命令执行前失败；
- 每个 suite 至少三个可复现场景，包含步骤和预期；
- `target_paths` 必须存在且在仓库内；
- local/CI suite 必须有正向 argv 命令和超时；manual/external suite 必须声明阻塞证据；
- 缺少工具、超时、非零退出、矩阵格式错误均 fail closed。

质量阈值沿用 `governance/ci-pipeline.json`：

- 单元测试失败数：`0`；关键跳过数：`0`；治理问题：`0`；阻断级安全发现：`0`；
- 代码行覆盖率下限：`80%`；变异测试下限：`60%`；
- 复式账本借贷差额：`0`；幂等副作用重复数：`0`；
- 性能必须满足模块 SLO、P99/错误率、容量余量和恢复目标；
- 外部证据不齐时认证门禁保持 `NOT_CERTIFIED`。

行覆盖率和变异分数必须由 CI 的真实工具（例如 JaCoCo、Coverage.py、Mutation testing tool）生成并附 commit/digest；本矩阵的 100% batch coverage 不能冒充 80% line coverage。

## 5. 可执行命令

```bash
# 校验矩阵结构、128 批次精确覆盖和可执行套件清单
python3 scripts/run-test-matrix.py --list

# 校验 testing/test_*.py 与 local slice 的 exact-set/唯一归属，新增漏绑立即失败
python3 scripts/run-code-suite.py --check-coverage

# 运行全部本地/CI 套件；外部套件会显示 BLOCKED
make test-matrix-local

# 运行完整 128-batch 矩阵并生成 JSON/JUnit 报告；允许外部阻塞保持可见
make test-matrix

# 严格模式：任何外部阻塞都使退出码非零，适用于发布前门禁
python3 scripts/run-test-matrix.py --json-out build/test-matrix/strict.json

# 按批次定位
python3 scripts/run-test-matrix.py --batch B114 --allow-blocked

# 原有治理/单元入口
make governance
make test
python3 -m unittest discover -s testing -p 'test_*.py' -v
./gradlew --no-daemon --console=plain test
node --test apps/admin-web/test/admin-domain.test.mjs apps/checkout-web/test/checkout.test.mjs apps/checkout-web/test/server.test.mjs sdks/server/node/elmpay-client.test.mjs
go -C sdks/server/go test ./...
DOTNET_ROOT=/usr/local/share/dotnet PATH=/usr/local/share/dotnet:$PATH dotnet run --project sdks/server/dotnet/tests/ElmPay.ContractTests.csproj --no-restore --nologo
```

## 6. 套件与场景目录

`testing/test-matrix.json` 将 128 个批次分成 21 个可执行/外部套件：

- B00–B07 治理、SSOT、追踪和证据；
- B08–B15 领域、金额、状态、事件、数据和拓扑；
- B16–B31 零信任、身份、MFA、授权、密钥、租户、商户和路由；
- B32–B39 Intent、Attempt、捕获、幂等和 Webhook；
- B40–B55 微信/支付宝/Stripe/PayPal/Apple Pay 契约与模拟器；
- B56–B71 Checkout、SDK、退款、争议、订阅、Mandate 和 Dunning；
- B72–B79 复式账本、手续费、结算、账单、对账和财务导出；
- B80–B87 风控信号、规则/ML、钓鱼、e-skimming、机器人和案件；
- B88–B103 Gateway/mesh/DB/Kafka/Redis/Kubernetes、多地域、遥测、SLO、SIEM、事件和容量；
- B104–B111 PCI、中国/全球隐私、AML/KYB、数据生命周期、SBOM、漏洞和第三方风险；
- B112–B115 属性/模型、渠道契约、Webhook 故障和并发；
- B116–B117 真实扫描编排、TEST-only loopback 压测以及队列/数据库/Provider 故障恢复；
- B118–B127 UAT、独立评审、迁移 shadow、生产上线、灰度、回滚、商业 SLA 和最终认证（external/blocking）。

每个场景的输入扰动、预期状态、目标路径和命令均以 JSON 保存，避免只写“应测试”而无法执行。新增批次时必须新增 suite 或扩展 `batch_ids`，运行器会因重复/缺失 ID 立即拒绝。新增 `testing/test_*.py` 时还必须在 `run-code-suite.py` 指定唯一 slice；未绑定测试不会被 discovery 静默吞掉。

关键闭环由以下 slice 显式执行：B40–B55 运行五 Provider 全渠道本地模拟器；B89 运行 default-deny/FQDN egress renderer 测试；B100 运行 payment-core durable account breaker 与 production dispatch 测试；B116 运行真实 scanner discovery/orchestration；B117 运行受 TEST token 保护的 loopback 峰值、突发、soak 与故障恢复测试。官方 Provider sandbox/认证和生产性能结果仍是 external evidence，不能由这些本地结果替代。

## 7. 缺陷、证据与退出标准

严重级别：

- **P0**：双扣/双退、账本不平、未验签履约、租户越权、密钥泄漏、生产数据破坏；立即阻断。
- **P1**：核心支付或退款不可用、关键 SLO/恢复目标失败、严重契约漂移；发布阻断。
- **P2**：可绕过的业务错误、非关键性能/可观测性缺陷；必须有 owner 和期限。
- **P3**：文档/体验问题；进入 backlog，不得改变安全/资金判定。

退出条件是：所有 local/CI suite PASS；矩阵无缺失/重复；质量阈值达到；P0/P1 为 0；报告、SBOM、扫描和构建产物可重算。除此之外，`B00 evidence` 仍保持未提交/未暂存，`0/128 NOT_CERTIFIED` 保持不变，直到外部证据和独立评审真实存在。

## 8. CI 与发布集成

CI 应在治理阶段之后执行 `make test-matrix-local`，上传 `build/test-matrix/*.json` 和 JUnit，但不能把它们写入 `evidence/` 或当作独立审查。若要改变 `.github/workflows/ci.yml`，必须先更新 `governance/ci-pipeline.json`，再运行 `python3 scripts/render-ci.py`，最后执行 `python3 scripts/render-ci.py --check`。

发布前必须额外运行严格模式并把外部证据 bundle 交给独立审核者；`review.json`、Provider 官方认证、PCI/UAT/DR/商户验收均由相应责任方提供。自动化测试通过只能说明代码在声明环境中通过，不能解除这些外部门禁。
