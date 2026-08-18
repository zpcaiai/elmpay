# ADR-0012: 单一版本目录驱动的可重复构建基线

- 状态：accepted
- 日期：2026-08-18
- 批次：B03
- 决策者：payment-platform-platform-eng payment-platform-architecture
- 关联需求：PAY-REQ-0040, PAY-REQ-0049
- 关联控制：NN-12, CTRL-011, CTRL-018
- 取代：无

## 背景

支付平台的构建必须可重复：同一提交在开发者机器、CI 与灾难恢复环境上必须产出同样的
依赖闭包。散落在 `build.gradle.kts`、`Dockerfile`、`compose.yaml` 与 CI 配置里的版本
号没有所有者、没有升级策略，也无法被审计；浮动版本（`latest`、`1.2.+`、`SNAPSHOT`）
会让供应链攻击在不修改任何一行代码的情况下进入生产。

## 决策

`governance/version-catalog.json` 是**唯一**的版本事实源：

1. 每个条目必须声明 `version`、`pin_type`、`source`、`owner` 与 `upgrade_policy`；
2. 版本必须是具体字符串——禁止范围语法、`latest`、`SNAPSHOT` 与 Gradle 动态版本；
   SemVer 构建元数据（如 Temurin `25.0.4+7`）视为精确版本；
3. 容器镜像必须以 `sha256:` 摘要固定，仅有 tag 不算固定；
4. 每个模块必须且只能属于一个构建系统（`gradle` 或 `node`）；
5. `gradle/libs.versions.toml`、`settings.gradle.kts`、`build.gradle.kts`、
   `.tool-versions`、`platform/toolchain/versions.env` 全部由目录**生成**，
   漂移即构建失败。

语言基线为 Java 25 LTS，框架基线为 Spring Boot 4.1.x，构建工具为 Gradle。

## 后果

新增依赖必须先进目录并指定所有者与升级策略，流程上比“直接写进 build 文件”慢；
换来的是任何版本变更都可被 diff、可被复核、可被回滚，并且构建在离线环境可重复。
`settings.gradle.kts` 由模块注册表生成，因此新增模块必须同时登记所有权与边界。

## 备选方案

（a）Gradle 版本目录作为唯一事实源：拒绝，TOML 无法承载 owner/upgrade_policy/摘要
等治理字段，也无法覆盖容器镜像与前端工具链；
（b）Renovate/Dependabot 自动升级为主：作为补充可行，但不能替代显式所有权，
且自动 PR 仍须通过本目录与门禁；
（c）不固定次要版本以便自动获得补丁：拒绝，等于把生产依赖交给上游发布节奏。

## 验证

`tools/paygov/toolchain.py` 与 `tools/tests/test_b03_toolchain.py`：
浮动版本、缺摘要、缺所有者、模块无构建系统、Java 主版本偏离、生成文件漂移
全部会使门禁失败。本环境无外网，具体 patch 版本尚未对官方发布渠道核验，
该缺口登记为剩余风险 `RR-06`，复审批次 B109。
