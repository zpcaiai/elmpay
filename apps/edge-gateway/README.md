# Edge Gateway

The Java application exposes authenticated, rate-limited Payment Intent create/read/confirm,
capture/cancel/void and unknown-outcome query endpoints with strict integer JSON, request tracing,
tenant identity derived from authenticated principals, security headers and bounded bodies. It has
an explicitly gated deterministic local sandbox and a PostgreSQL mode with checksum-bound migrations.
Production readiness remains gated on real provider certification and runtime evidence.

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
Before disclosing public provider SDK parameters, the
`/api/checkout/sessions/{id}/provider-sdk-config` route revalidates the signed session against the
authoritative payment intent and a currently healthy tenant/project/merchant provider account.
Provider/version bindings come only from the checked-in `provider-sdk-runtime.json`; script URLs and
integrity values remain exclusively owned by checkout-web. Every successful disclosure is recorded
in the append-only, forced-RLS `checkout_provider_sdk_audit` table with session, channel,
configuration, business-order and capability digests. The OAuth form of the route requires
`payments.read`; the browser form accepts only the current `CheckoutSession` token.
Production startup fails closed unless the database settings and these checkout values exist:
`ELMPAY_CHECKOUT_SIGNING_KEY_ID`, `ELMPAY_CHECKOUT_SIGNING_KEY_FILE`,
`ELMPAY_CHECKOUT_RETURN_ROUTES`, `ELMPAY_CHECKOUT_DEFAULT_RETURN_ROUTE_ID`,
`ELMPAY_CHECKOUT_ALLOWED_METHODS`, `ELMPAY_CHECKOUT_PUBLIC_BASE_URL` (absolute HTTPS in
production, with no credentials, query, or fragment), and
`ELMPAY_CHECKOUT_REGION`. Production confirmation also requires a PSP/wallet-issued external
payment-method reference; the synthetic reference is local-sandbox-only.

Every PostgreSQL runtime uses the same non-overridable connection policy. Non-secret configuration
is supplied by `ELMPAY_DATABASE_URL` and `ELMPAY_DATABASE_USERNAME`; the URL must be a
credential-free `jdbc:postgresql://host:port/database` value without query parameters. Password,
CA, client certificate and PKCS#8 client key are read from the absolute read-only mounts named by
`ELMPAY_DATABASE_PASSWORD_FILE`, `ELMPAY_DATABASE_CA_FILE`,
`ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE`, and
`ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE`. The password is reread for every connection so secret
rotation does not require a process restart. The JDBC client always uses `sslmode=verify-full` and
callers cannot override the mounted identity. Checkout signing material is loaded only from
`ELMPAY_CHECKOUT_SIGNING_KEY_FILE` (canonical unpadded base64url). The synchronous risk gate no
longer accepts HMAC or loopback HTTP: it uses TLS 1.3 mTLS files
`ELMPAY_RISK_CLIENT_CERTIFICATE_FILE`, `ELMPAY_RISK_CLIENT_PRIVATE_KEY_FILE` and
`ELMPAY_RISK_CA_BUNDLE_FILE`, obtains a server nonce, and verifies the complete
tenant/project/request/digest response binding.

Production (`ELMPAY_RUNTIME_MODE=postgres`) rejects the local hashed API-key sandbox, including a
stray `ELMPAY_API_PRINCIPALS` configuration.
It requires a short-lived RS256 OAuth access token whose tenant, project, merchant, audience,
scope and client identity are exact claims, the JOSE `typ` is exactly `at+jwt`, and the token is
bound by `cnf.x5t#S256` to the TLS peer certificate. The gateway itself terminates TLS 1.3 with
`needClientAuth=true` and computes the thumbprint from the `HttpsExchange` peer X.509 DER bytes.
`X-ELMPAY-Client-Certificate-SHA256` is forbidden rather than trusted.
The verifier loads `ELMPAY_OIDC_JWKS_FILE` from a read-only local mount and checks a fresh,
RS256-signed `ELMPAY_OIDC_REVOCATION_FILE` on every request (schema:
`platform/security/oidc-revocation-snapshot.schema.json`); stale, missing, malformed, revoked or
unbound tokens fail closed. Issuer and audience are configured by `ELMPAY_OIDC_ISSUER` and
`ELMPAY_OIDC_AUDIENCE`.

The production business listener defaults to HTTPS port 8443 and requires read-only mounted server
certificate, PKCS#8 private key and client-CA files. Startup validates time, SAN/server name,
server-auth/key-usage purpose, certificate/private-key match, chain order and CA constraints. A
separate probe-only HTTP listener (`ELMPAY_HEALTH_PORT`, default 8081) serves only the three health
paths and is deliberately absent from the business Service. Local sandbox mode may use loopback
HTTP and API keys, but must still be explicitly enabled.

Dispute, subscription-renewal and dunning results never accept a `verified=true` assertion.
Provider verifier/query workloads submit short-lived Ed25519 receipts bound to the exact tenant,
project, provider, object, outcome and payload digest. Production loads their public trust roots
from `ELMPAY_PROVIDER_EVIDENCE_TRUST_FILE` (schema:
`platform/security/provider-evidence-trust.schema.json`) and persists nonce replay state under RLS.
Provider certification and production trust material remain external release gates.

Tenant activation and closure use a separate authority trust domain. In `postgres` mode startup
requires `ELMPAY_TENANT_EVIDENCE_TRUST_FILE` to resolve to a bounded UTF-8 document on a read-only
filesystem or a non-writable file inside a non-writable mount directory (schema:
`platform/security/tenant-evidence-trust.schema.json`). Writable, missing, malformed, unknown-type,
revoked or expired trust material fails startup before migrations. The resulting verifier uses the
tenant-RLS durable replay guard; no production constructor substitutes in-memory trust or replay
state.
