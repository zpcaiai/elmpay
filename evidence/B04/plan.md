# B04 plan — 本地开发平台与测试容器

Batch: 本地开发平台与测试容器 · Wave W00 · Skill `pay-dev-platform-ci` · depends_on: [B03]

## 1. 范围

提供**离线可重复**的 PostgreSQL、Kafka、Redis、OIDC、对象存储与渠道模拟环境：

1. `governance/dev-platform.json`：5 个基础服务 + 5 个渠道模拟器，
   端口、健康检查、环境变量、卷与数据分类全部声明化。
2. 生成式平台文件：`platform/dev/compose.yaml`、`.env.example`、`README.md`、
   每个模拟器的 `Dockerfile`（`tools/paygov/devgen.py`）。
3. `tools/simulator/provider_sim.py`：**可真实运行**的零依赖渠道模拟器
   （健康检查、幂等创建、签名回调信封、卡号形状拒绝、生产凭证拒绝启动）。
4. `tools/paygov/devplatform.py`：本地平台门禁。
5. `scripts/dev-up.sh`：启动并等待全部 healthy，先校验生成文件无漂移再启动。
6. `tools/tests/test_b04_simulator.py`（18 例）与 `test_b04_dev_platform.py`（25 例）。

## 2. 受影响组件

`governance/dev-platform.json`、`governance/version-catalog.json`（新增 keycloak/minio/python 条目
→ B03 需重新基线）、`tools/paygov/{devgen,devplatform}.py`、`tools/simulator/`、
`platform/dev/`、`scripts/{render-dev-platform.py,dev-up.sh}`。

## 3. 领域接口与数据契约

- 平台声明契约：`environments` ⊆ {local, integration}；
  `forbidden_in_environments` 的三项必须为 `false`；
  每个服务/模拟器必须声明 `data_classification = synthetic`、健康检查、端口与镜像来源。
- 镜像必须来自版本目录且为 `pin_type=digest`；模拟器以仓库根为构建上下文本地构建。
- 密钥类环境变量必须是 `${VAR}` 引用且在 `secret_env_vars` 中登记，禁止内联字面量。
- 模拟器 HTTP 契约：
  `GET /healthz` → `{status, provider, mode:"simulator", data:"synthetic"}`；
  `POST /payments`（必须带 `Idempotency-Key`）→ 201 首次 / 200 重放 / 409 同键异载荷 / 422 卡号形状；
  `GET /payments/{id}` → 200 或 404；
  `POST /_sim/callback` → `{timestamp, nonce, body, signature}`，
  签名为 `HMAC-SHA256(secret, "ts.nonce.body")`，验签窗口 300 秒。

## 4. 错误语义

`DEV_ENVIRONMENT`、`DEV_FORBIDDEN`、`DEV_DATA_CLASS`、`DEV_HEALTHCHECK`、`DEV_IMAGE`、
`DEV_INLINE_SECRET`、`DEV_PRODUCTION_VALUE`、`DEV_PORT_CONFLICT`、`DEV_PORT_EXPOSURE`、
`DEV_CONTAINER_PRIVILEGE`、`DEV_VOLUME`、`DEV_REQUIRED_SERVICE`、`DEV_SIMULATOR_MISSING`、
`DEV_BUILD_CONTEXT`、`DEV_DRIFT`、`DEV_MISSING`、`DEV_DUPLICATE`。
另新增 `VALIDATOR_CRASHED`：任何校验器异常一律以退出码 3 fail closed，不再以未捕获异常退出。

## 5. 命令

```bash
python3 scripts/render-dev-platform.py --check
python3 -m tools.paygov.cli verify dev-platform --repo .
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
scripts/dev-up.sh          # 需要 docker，本证据环境不可用，见第 8 节
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 模拟器在真实 socket 上启动并应答；平台声明与生成文件一致；端口仅绑定 127.0.0.1；无 privileged / host 网络 |
| 幂等 | 同键同载荷返回首次结果；**16 线程并发重放只产生一个 payment，且只有一次 201** |
| 拒绝 | 缺幂等键 400；同键异载荷 409；卡号形状 422；未知资源 404 |
| 签名 | 正确签名验证通过；篡改 body、错误密钥、过期时间戳一律失败 |
| 安全 | 模拟器在非合成密钥、生产标记商户号、未知渠道时**拒绝启动** |
| 平台拒绝 | 内联口令、未登记密钥变量、生产标记值、非合成数据分类、production 环境、允许真实卡数据、缺必需服务、缺模拟器、端口冲突、缺健康检查、镜像不在目录、未声明卷、手改 compose、生成文件缺失、构建上下文不存在 |
| 运行期 | 负向控制扩至 33 个场景（新增 7 个 B04 场景） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-dev-platform.py`。
本地平台通过 `scripts/dev-up.sh --down` 拆除，卷保留以便复现问题。

## 8. 已知限制（诚实声明）

本证据环境**没有 Docker 也没有外网**，因此：

- `compose.yaml` 的实际拉起未在本批次执行；证据覆盖的是**声明与生成的正确性**
  以及**模拟器进程的真实运行**（18 个用例在真实 HTTP socket 上通过）。
- 容器镜像摘要仍是占位值，登记为剩余风险 `RR-06`（复审批次 B109）。
- 容器编排的实际健康与恢复行为将在 B05（CI）与 B95（演练）中补齐运行证据。

不把上述缺口写成“已完成”，是 NN-12 的直接要求。

## 9. 数据迁移

无。PostgreSQL 容器仅提供空实例，schema 迁移从 B13 开始。

## 10. 证据与审查

`evidence/B04/`；执行者 `claude-agent`，独立审查者 `Ethan`。
本批次修改了 B00 与 B03 的产物，因此提交后统一重新基线 B00–B03。

## 11. 威胁变化

新增攻击面与对应控制：

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 本地平台声明成为新的配置事实源 | 被篡改后可让本地环境持有生产凭证或真实数据（AC-05、AC-08） | 内联口令、生产标记值、非合成数据分类一律 fail closed；密钥必须为已登记的 `${ENV}` 引用 |
| 引入可运行的渠道模拟器 | 模拟器若被误用于生产或被塞入真实密钥，会成为凭证泄露点（AC-05） | 模拟器在非 `sim-` 前缀密钥、生产标记商户号、未知渠道时**拒绝启动**；对卡号形状载荷返回 422 |
| 本地暴露 10 个服务端口 | 局域网内横向探测与未授权访问（AC-08） | 生成的 compose 仅绑定 `127.0.0.1`；禁止 host 网络与 privileged；统一 `no-new-privileges` |
| 容器镜像摘要仍为占位值 | 供应链替换（AC-12） | 登记为剩余风险 `RR-06`，到期 2026-12-16，复审批次 B109；同时强制 digest 字段格式 |

本批次未新增被接受的高危剩余风险；`RR-06` 已在 B03 登记并继续生效。
