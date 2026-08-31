# Webhook ingress

`WebhookIngressService` selects a provider verifier, authenticates the exact bounded raw body before
any database access, rejects raw card fields, and only then writes the verified event through
`DataSourceWebhookInbox`. Raw request bytes are erased from request-owned buffers after synchronous
verification and are never stored; PostgreSQL retains only `raw_body_sha256`, a versioned typed
canonical event, and immutable verification digests. Provider free-form fields are size/control
validated, sensitive fields are rejected, and unknown fields are omitted from the canonical schema.

## Durable effect processing

`WebhookInboxProcessor` processes one tenant-scoped event at a time. Its PostgreSQL store uses an
atomic `FOR UPDATE SKIP LOCKED` claim, expiring leases, monotonic fencing tokens, bounded
exponential backoff, terminal maximum attempts, and digest-only diagnostics. A stale lease can be
reclaimed; a stale owner cannot acknowledge or reschedule it.

The configured `WebhookEffectPort` receives explicit typed event fields, canonical schema bytes,
and immutable verifier metadata. It must use the supplied JDBC connection for payment/commerce
writes and for any external-effect outbox record. The effect commit marker, dispatcher writes, and
`PROCESSED` transition commit or roll back together, preventing a crash retry from duplicating a
database business effect. Direct network calls from this port are forbidden.

`WebhookProcessorApplication` is the deployable, health-only asynchronous process. It discovers a
bounded page of due tenants through the narrowly granted
`elmpay_claimable_webhook_tenants` function, advances a round-robin cursor, and invokes `runOnce`
once per tenant per cycle. Each replica receives its lease identity from the Pod name through the
downward API. Startup fails when the database role is superuser/BYPASSRLS, lacks the discovery
grant, or any required table, column, or FORCE-RLS control is absent. PostgreSQL password, CA,
client certificate and private key are loaded only from read-only mounted files and the driver is
forced to `sslmode=verify-full`.

`PaymentCoreWebhookEffectAdapter` accepts only the explicit `provider-event-map.v1` Stripe,
WeChat, Alipay and PayPal event allowlist. Unknown or semantically ambiguous types are permanently
quarantined. `ProviderWebhookEffectService` rebinds every event to exactly one tenant/project,
provider account, provider object and durable business order. Money must match immutable payment,
refund, or capture-expectation facts. Terminal state cannot be downgraded, partial capture/refund
cannot exceed the aggregate, and duplicate/out-of-order effects create explicit no-op application
facts. Payment/refund mutation, database-owned semantic outbox revision, effect-commit marker and
inbox `PROCESSED` share one caller-owned JDBC transaction; no network call occurs.

Webhook verification metadata is an internal trust assertion. This module does **not** create a
`ProviderEvidenceReceipt`, does not use an external-provider Ed25519 identity, and must not be
presented as provider-official evidence. A future platform attestation requires a separately named
trust schema and a private key loaded from a read-only mount. This runtime intentionally emits no
such attestation and never represents its internal digest as an external provider signature.

The PostgreSQL edge runtime wires account-bound production provider adapters through
`ProviderWebhookVerifiers`, resolves an opaque endpoint token, and exposes
`POST /v1/provider-webhooks/{token}`. Provider sandbox and certification callbacks remain `NOT_RUN`.
This source-level runtime and its desired Kubernetes policy are not production-cluster, merchant
UAT, provider certification, PCI, penetration-test, or multi-region evidence.
