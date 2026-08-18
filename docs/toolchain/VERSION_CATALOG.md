<!-- GENERATED FILE — do not edit by hand.
     Source of truth: governance/version-catalog.json
     Regenerate with: python3 scripts/render-docs.py -->

# 版本目录（B03）

核验状态：`unverified-offline`。本环境无外网，具体 patch 版本尚未对官方发布渠道核验；见 governance/threat-model.json 的 RR-06。

所有版本必须精确固定；容器镜像必须以摘要固定。构建文件由本目录生成，漂移即失败。

| ID | 名称 | 类别 | 版本 | 固定方式 | 责任人 | 升级策略 |
| --- | --- | --- | --- | --- | --- | --- |
| jdk | Eclipse Temurin JDK | jdk | 25.0.4+7 | exact | payment-platform-platform-eng | LTS；仅接受同一 LTS 线的安全补丁，跨大版本需 ADR |
| spring-boot | Spring Boot | framework | 4.1.3 | exact | payment-platform-architecture | 次版本季度评估；破坏性变更需 ADR 与迁移批次 |
| spring-cloud | Spring Cloud | framework | 2026.0.2 | exact | payment-platform-architecture | 跟随 Spring Boot 版本矩阵 |
| gradle | Gradle | build | 9.2.1 | exact | payment-platform-platform-eng | wrapper 校验和锁定；升级需绿色 CI 两轮 |
| kotlin | Kotlin (仅构建脚本) | build | 2.3.0 | exact | payment-platform-platform-eng | 仅用于 Gradle KTS，不用于生产代码 |
| postgresql | PostgreSQL | database | 18.2 | exact | payment-platform-sre | 次版本一月内跟进；大版本升级需 B90 演练 |
| flyway | Flyway | migration | 11.9.0 | exact | payment-platform-architecture | 迁移必须可回滚或前向兼容 |
| kafka | Apache Kafka | messaging | 4.2.0 | exact | payment-platform-sre | 仅作可重放事件日志，不作事实源 |
| redis | Redis | cache | 8.2.1 | exact | payment-platform-sre | 仅限流与可丢失缓存 |
| kubernetes | Kubernetes | runtime-platform | 1.36.2 | exact | payment-platform-sre | 落后上游不超过两个次版本 |
| opentelemetry-java | OpenTelemetry Java Agent | observability | 2.20.0 | exact | payment-platform-sre | 脱敏处理器必须随升级回归 |
| grpc-java | gRPC Java | framework | 1.72.0 | exact | payment-platform-connectors | Provider Adapter 契约实现 |
| protobuf | Protocol Buffers | framework | 4.30.1 | exact | payment-platform-connectors | 仅相加式 schema 演进 |
| junit | JUnit | testing | 5.13.2 | exact | payment-platform-platform-eng | 禁止跳过关键测试 |
| testcontainers | Testcontainers | testing | 1.22.0 | exact | payment-platform-platform-eng | 本地与 CI 使用同一镜像摘要 |
| jqwik | jqwik 属性测试 | testing | 1.9.4 | exact | payment-platform-finance | 金额、状态机与账本不变量的属性测试 |
| node | Node.js | frontend | 24.9.0 | exact | payment-platform-architecture | 仅用于 checkout-web / admin-web 构建 |
| pnpm | pnpm | frontend | 10.14.0 | exact | payment-platform-architecture | lockfile 必须提交 |
| postgres-image | postgres 容器镜像 | container | 18.2-bookworm | digest | payment-platform-sre | 摘要待 B04 在可联网构建代理上锁定 |
| redis-image | redis 容器镜像 | container | 8.2.1-bookworm | digest | payment-platform-sre | 摘要待 B04 锁定 |
| kafka-image | kafka 容器镜像 | container | 4.2.0 | digest | payment-platform-sre | 摘要待 B04 锁定 |

## 构建系统归属

| 构建系统 | 模块 |
| --- | --- |
| gradle | money、domain-events、idempotency、audit、security、observability、wechat-pay、alipay、stripe、paypal、apple-pay、payment-core、webhook-ingress、webhook-delivery、merchant-config、risk-engine、ledger-service、reconciliation-service、worker-scheduler、edge-gateway |
| node | checkout-web、admin-web |

## 生成的构建文件

`gradle/libs.versions.toml`、`settings.gradle.kts`、`build.gradle.kts`、
`.tool-versions`、`platform/toolchain/versions.env`

重新生成：`python3 scripts/render-build.py`
