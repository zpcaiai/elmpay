# B03 plan — 单仓工具链与版本目录

Batch: 单仓工具链与版本目录 · Wave W00 · Skill `pay-architecture-toolchain` · depends_on: [B01]

## 1. 范围

建立 Java 25 / Spring Boot 4.1 / Gradle / 前端 / 数据库 / 基础设施的**可重复构建基线**：

1. `governance/version-catalog.json`：21 个条目，覆盖 12 个必需类别，
   每条含 `version` / `pin_type` / `source` / `owner` / `upgrade_policy`。
2. 生成式构建文件：`gradle/libs.versions.toml`、`settings.gradle.kts`、`build.gradle.kts`、
   `.tool-versions`、`platform/toolchain/versions.env`（`tools/paygov/buildgen.py`）。
3. `tools/paygov/toolchain.py`：浮动版本、缺摘要、缺所有者、模块无构建系统、
   Java 主版本偏离、生成文件漂移一律 fail closed。
4. `docs/adr/0012-pinned-toolchain-baseline.md`、`docs/toolchain/VERSION_CATALOG.md`（生成）。
5. `tools/tests/test_b03_toolchain.py`：25 个用例。

## 2. 受影响组件

`governance/version-catalog.json`、`tools/paygov/{buildgen,toolchain}.py`、
`scripts/render-build.py`、仓库根构建文件、`platform/toolchain/`、`docs/adr/`、`docs/toolchain/`。
同时更新 `governance/threat-model.json`（新增 `RR-06`）——因此 B02 需要重新基线。

## 3. 领域接口与数据契约

- 目录条目契约：`id`、`name`、`category`、`version`、`pin_type`(`exact`|`digest`)、
  `digest`、`source`、`owner`、`upgrade_policy`。
- 版本语义：具体字符串；禁止 `latest` / `SNAPSHOT` / `RELEASE` / 范围语法 / Gradle 动态版本；
  SemVer 构建元数据（Temurin `25.0.4+7`）判为精确。
- 容器条目必须 `pin_type=digest` 且 `digest` 匹配 `sha256:[a-f0-9]{64}`。
- 模块→构建系统为**全覆盖且互斥**的划分；`settings.gradle.kts` 的 include 列表由
  模块注册表的 `path` 生成，因此新增模块必须先登记所有权与边界。
- 版本策略：目录自身 `schema_version` 语义化版本；升级需 CODEOWNERS 复核。

## 4. 错误语义

`TOOLCHAIN_VERSION_FORMAT`、`TOOLCHAIN_FLOATING`、`TOOLCHAIN_PIN`、`TOOLCHAIN_DIGEST`、
`TOOLCHAIN_METADATA`、`TOOLCHAIN_CATEGORY`、`TOOLCHAIN_BUILD_SYSTEM`、`TOOLCHAIN_JDK`、
`TOOLCHAIN_DUPLICATE`、`TOOLCHAIN_VERIFICATION`、`BUILD_DRIFT`、`BUILD_MISSING`。

## 5. 命令

```bash
python3 scripts/render-build.py --check
python3 -m tools.paygov.cli verify toolchain --repo .
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
python3 .payment-platform/skill-package/scripts/orchestrate.py validate B03 --repo .
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 21 条目全部通过；生成 5 个构建文件且确定性；模块划分全覆盖互斥；Java 25 / Spring Boot 4.1 基线 |
| 拒绝 | `latest`、`SNAPSHOT`、`1.72.+`、`[5.13,6.0)`、容器缺摘要、容器仅 tag 固定、缺所有者、缺升级策略、模块无构建系统、模块被两个构建系统认领、Java 降级、必需类别缺失、手改构建文件、生成文件缺失、无核验说明 |
| 正向边界 | SemVer 构建元数据 `25.0.5+9` 必须被接受（避免过度拦截） |
| 超时 | `--budget-seconds 0` 返回 3 |
| 重复 | `render-build.py --check` 与 `verify-all` 重复运行结果一致 |
| 运行期 | 负向控制扩至 26 个场景，新增 5 个 B03 场景 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-build.py` 即可恢复一致状态。

## 8. 威胁变化

新增资产暴露面：版本目录被篡改可在不改一行业务代码的情况下引入恶意依赖（AC-12）。
控制：CODEOWNERS 复核 + 精确固定 + 摘要固定 + 生成文件漂移检测。
**新增剩余风险 `RR-06`**：离线环境下具体 patch 版本与镜像摘要尚未对官方发布渠道核验；
补偿控制为精确固定与漂移检测，到期日 2026-12-16，复审批次 B109。

## 9. 数据迁移

无。Flyway 已进入目录，迁移能力在 B13 之后启用，届时要求可回滚或前向兼容。

## 10. 证据与审查

`evidence/B03/`；执行者 `claude-agent`，独立审查者 `Ethan`。
本批次修改了 B02 的产物（威胁模型），因此 B00–B02 在提交后统一重新基线。
