// GENERATED FILE — do not edit by hand.
// Source of truth: governance/version-catalog.json
// Regenerate with: python3 scripts/render-build.py

rootProject.name = "elmpay"

include(":libs:money")
include(":libs:domain-events")
include(":libs:idempotency")
include(":libs:audit")
include(":libs:security")
include(":libs:observability")
include(":connectors:wechat-pay")
include(":connectors:alipay")
include(":connectors:stripe")
include(":connectors:paypal")
include(":connectors:apple-pay")
include(":services:payment-core")
include(":services:webhook-ingress")
include(":services:webhook-delivery")
include(":services:merchant-config")
include(":services:risk-engine")
include(":services:ledger-service")
include(":services:reconciliation-service")
include(":services:worker-scheduler")
include(":apps:edge-gateway")

// Node-built modules are not Gradle projects:
//   checkout-web -> apps/checkout-web (pnpm)
//   admin-web -> apps/admin-web (pnpm)
