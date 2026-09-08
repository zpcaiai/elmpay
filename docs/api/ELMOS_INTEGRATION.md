# ELMOS hosted-checkout integration

This integration uses the existing tenant/project-bound hosted checkout and signed business
webhook contracts. It does not move ELMOS business-order or Credit state into ELMPay.

## Checkout contract

ELMOS calls `POST /v1/checkout-sessions` with OAuth/API bearer authentication, mTLS in production,
`X-Project-Id`, `Idempotency-Key`, `X-Request-Id`, `traceparent`, and a body containing only:

- `business_order_no`
- integer `amount` in minor units
- `currency` (`CNY`)
- allowlisted `return_route_id`

The create response now includes the additive `payment_intent_id` field alongside
`checkout_session_id`, `expires_at`, `checkout_url`, and `status`. Existing clients may ignore the
new field; ELMOS validates it as a UUID.

## Business webhook delivery

`WebhookFanoutPublisher` runs in worker-scheduler between the transactional domain outbox and the
Kafka publisher. For every active endpoint of the exact tenant/project it enqueues the canonical
event envelope in `webhook_delivery_outbox`, then publishes the same event to Kafka. Enqueue is
idempotent on `(tenant_id, endpoint_id, event_id)`; a partial failure is retried and cannot create a
second delivery row.

The existing webhook delivery worker signs the exact raw envelope and sends:

- `X-Elmpay-Event-Id`
- `X-Elmpay-Event-Type`
- `X-Elmpay-Timestamp`
- `X-Elmpay-Key-Id`
- `X-Elmpay-Signature: t=<unix-seconds>,v1=<base64url-hmac-sha256>`

ELMOS fulfills only `payment_intent.captured` version 1. Other valid event types are acknowledged
without order effects. The captured payload exposes only `business_order_digest`, never the raw
ELMOS order number.

## Operational prerequisites

Provision the ELMOS endpoint and project signing key through an approved administration workflow.
The worker runtime role needs `SELECT` on `webhook_endpoint` and
`SELECT, INSERT, UPDATE` on `webhook_delivery_outbox`; it receives no endpoint-administration or
dead-letter replay authority. Signing secrets continue to come from the mounted, short-lived
secret lease service rather than PostgreSQL or environment variables.

Local unit/E2E tests are engineering evidence only. Provider execution, real CNY payment,
deployment, independent verification, and production certification remain `NOT_RUN` /
`NOT_CERTIFIED` until separately authorized and evidenced.
