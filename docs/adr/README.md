<!-- GENERATED FILE — do not edit by hand.
     Source of truth: docs/adr/*.md
     Regenerate with: python3 scripts/render-docs.py -->

# 架构决策记录索引

共 14 条 ADR。新增决策必须新建 ADR，不得原地改写既有决策；
被取代的 ADR 状态改为 `superseded`，并由取代它的 ADR 在“取代”字段中声明。

| ADR | 标题 | 状态 | 日期 | 批次 | 关联控制 |
| --- | --- | --- | --- | --- | --- |
| [ADR-0001](0001-monorepo-modular-boundaries.md) | 单仓多模块，先合并部署后可拆分 | accepted | 2026-08-18 | B02 | NN-01 |
| [ADR-0002](0002-business-orders-stay-out.md) | 业务订单不迁入支付平台 | accepted | 2026-08-18 | B02 | NN-01 |
| [ADR-0003](0003-integer-minor-units.md) | 金额一律使用最小货币单位整数 | accepted | 2026-08-18 | B02 | NN-05 |
| [ADR-0004](0004-server-verified-payment-truth.md) | 支付定责只依据验签事件或服务端查询 | accepted | 2026-08-18 | B02 | NN-03, NN-08, CTRL-002 |
| [ADR-0005](0005-idempotency-inbox-outbox.md) | 幂等键加持久 Inbox/Outbox 实现恰好一次业务效果 | accepted | 2026-08-18 | B02 | NN-04, CTRL-003 |
| [ADR-0006](0006-postgres-source-of-truth.md) | PostgreSQL 为事实源，Kafka 只做可重放事件，Redis 不承载最终状态 | accepted | 2026-08-18 | B02 | CTRL-008, CTRL-013 |
| [ADR-0007](0007-no-raw-card-data.md) | 卡数据零接触：托管字段与 PSP 令牌 | accepted | 2026-08-18 | B02 | NN-02, CTRL-001 |
| [ADR-0008](0008-kms-managed-keys.md) | 密钥由 KMS/HSM/Vault 管理且不落地 | accepted | 2026-08-18 | B02 | NN-07, CTRL-006 |
| [ADR-0009](0009-zero-trust-access.md) | 零信任：服务 mTLS、管理员 WebAuthn、RBAC/ABAC/SoD | accepted | 2026-08-18 | B02 | NN-11, CTRL-004, CTRL-014 |
| [ADR-0010](0010-dependency-free-governance.md) | 治理工具链零第三方依赖 | accepted | 2026-08-18 | B02 | NN-12, CTRL-011 |
| [ADR-0011](0011-evidence-bound-to-commit.md) | 证据绑定提交并支持重新基线 | accepted | 2026-08-18 | B02 | NN-12, CTRL-020 |
| [ADR-0012](0012-pinned-toolchain-baseline.md) | 单一版本目录驱动的可重复构建基线 | accepted | 2026-08-18 | B03 | NN-12, CTRL-011, CTRL-018 |
| [ADR-0013](0013-toolchain-interpreter-floor.md) | 治理工具链的解释器地板固定为 Python 3.10 | superseded | 2026-08-20 | B03 | NN-12, CTRL-011, CTRL-018 |
| [ADR-0014](0014-exact-python-ci-toolchains.md) | CI 同时固定 Python 参考解释器与兼容地板 | accepted | 2026-08-26 | B05 | NN-12, CTRL-011, CTRL-018 |
