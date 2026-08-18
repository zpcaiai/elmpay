
# 目标代码仓库布局

```text
apps/
  edge-gateway/
  checkout-web/
  admin-web/
services/
  payment-core/
  webhook-ingress/
  webhook-delivery/
  merchant-config/
  risk-engine/
  ledger-service/
  reconciliation-service/
  worker-scheduler/
connectors/
  wechat-pay/
  alipay/
  stripe/
  paypal/
  apple-pay/
libs/
  money/
  domain-events/
  idempotency/
  audit/
  security/
  observability/
contracts/
  openapi/
  asyncapi/
  protobuf/
platform/
  terraform/
  kubernetes/
  policies/
docs/
evidence/
```

每个模块必须声明 owner、数据表、出入 API/事件、允许依赖、SLO、威胁和迁移策略。禁止连接器直接访问业务项目数据库，禁止后台绕过公开领域服务修改支付状态。
