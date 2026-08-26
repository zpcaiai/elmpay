# Edge Gateway

The Java application exposes authenticated, rate-limited Payment Intent create/read/confirm,
capture/cancel/void and unknown-outcome query endpoints with strict integer JSON, request tracing,
tenant identity derived only from hashed API principals, security headers and bounded bodies. It has
an explicitly gated deterministic local sandbox and a PostgreSQL mode with checksum-bound migrations.
Production readiness remains gated on real provider adapters, hardened proxy/TLS and runtime evidence.

Hosted checkout uses the OpenAPI route `/v1/checkout-sessions` for authenticated create/get/confirm
operations. `X-Project-Id` must match the authenticated principal, amounts are integer `amount`
minor units, and redirects are selected only by a pre-registered `return_route_id`. Browser calls use
`/api/checkout/sessions/{id}` with a derived `CheckoutSession` bearer; the platform Bearer credential
is neither accepted nor exposed on that route. The bearer is placed in the public checkout URL
fragment, never its request target.

Local mode uses an in-memory store only behind `ELMPAY_ENABLE_LOCAL_SANDBOX=true`. PostgreSQL mode
uses `JdbcCheckoutSessionRepository` and migration `V056__checkout_sessions.sql`, whose tenant RLS,
unique create key, and payment-intent uniqueness make restart and multi-instance replays safe. The
table stores signing claims and a key version but never the raw browser bearer or signing key.
Production startup fails closed unless the database settings and these checkout values exist:
`ELMPAY_CHECKOUT_SIGNING_KEY_ID`, `ELMPAY_CHECKOUT_SIGNING_KEY_B64`,
`ELMPAY_CHECKOUT_RETURN_ROUTES`, `ELMPAY_CHECKOUT_DEFAULT_RETURN_ROUTE_ID`,
`ELMPAY_CHECKOUT_ALLOWED_METHODS`, `ELMPAY_CHECKOUT_PUBLIC_BASE_URL`, and
`ELMPAY_CHECKOUT_REGION`. Production confirmation also requires a PSP/wallet-issued external
payment-method reference; the synthetic reference is local-sandbox-only.
