# GENERATED FILE — do not edit by hand.
# Source of truth: governance/dev-platform.json
# Regenerate with: python3 scripts/render-dev-platform.py

# 本地开发平台（B04）

离线可重复：所有镜像以摘要固定，模拟器只用 Python 标准库构建，无需包索引。

```bash
cp platform/dev/.env.example platform/dev/.env   # 仅本地合成口令
scripts/dev-up.sh                                 # 启动并等待全部 healthy
scripts/dev-up.sh --down                          # 停止
```

| 服务 | 用途 | 端口 | 数据分类 |
| --- | --- | --- | --- |
| postgres | 关系型事实源 | 5432→5432 | synthetic |
| kafka | 可重放事件日志 | 9092→9092 | synthetic |
| redis | 限流与可丢失缓存 | 6379→6379 | synthetic |
| keycloak | 本地 OIDC 提供方 | 8180→8080 | synthetic |
| minio | 本地对象存储（账单与导出） | 9000→9000, 9001→9001 | synthetic |
| wechat-sim | 微信支付 APIv3 模拟器 | 18081→8080 | synthetic |
| alipay-sim | 支付宝开放平台模拟器 | 18082→8080 | synthetic |
| stripe-sim | Stripe 模拟器 | 18083→8080 | synthetic |
| paypal-sim | PayPal Orders v2 模拟器 | 18084→8080 | synthetic |
| applepay-sim | Apple Pay 商户验证模拟器 | 18085→8080 | synthetic |

## 硬性约束

- 环境仅限 `local`、`integration`。
- **禁止**生产凭证、真实卡数据与真实个人信息；所有数据分类必须是 `synthetic`。
- 端口只绑定 `127.0.0.1`，不暴露到局域网。
- 容器统一 `no-new-privileges`，不使用 host 网络，不使用 privileged。
- 模拟器在检测到疑似生产凭证或卡号形状的数据时**拒绝启动/拒绝请求**。
