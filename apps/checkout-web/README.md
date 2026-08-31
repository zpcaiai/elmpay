# ElmPay hosted checkout web

This service hosts the no-inline-script checkout UI and reverse-proxies only
`/api/checkout/sessions/{id}` and `/confirm` to the edge gateway. The browser
receives a short-lived signed checkout credential in the URL **fragment**,
moves it to `sessionStorage`, clears browser history, and sends it as
`Authorization: CheckoutSession …`. Platform OAuth/API credentials are never
shipped to browser code.

The edge gateway is authoritative for every displayed state. A return page,
deep link, browser callback, or network error is never mapped to payment
success. Only the payment-core state resulting from a verified provider result
can produce `SUCCEEDED`.

Runtime configuration is explicit:

- Local: `ELMPAY_CHECKOUT_WEB_MODE=local` and
  `ELMPAY_ENABLE_LOCAL_SANDBOX=true`; `ELMPAY_API_BASE_URL` may be loopback HTTP.
- Production: `ELMPAY_CHECKOUT_WEB_MODE=production` and an HTTPS
  `ELMPAY_API_BASE_URL` without embedded credentials. The edge origin is pinned and contacted only
  with a read-only mounted client certificate/private key/trust bundle using TLS 1.3; configure
  `ELMPAY_EDGE_CLIENT_CERTIFICATE_FILE`, `ELMPAY_EDGE_CLIENT_PRIVATE_KEY_FILE`,
  `ELMPAY_EDGE_TRUST_BUNDLE_FILE`, and an exact `ELMPAY_EDGE_TLS_SERVER_NAME`. Production also requires
  `ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE`, an absolute read-only mount containing
  a canonical base64url value with at least 32 random bytes. All replicas serving one checkout origin must use the
  same key so a short-lived frame ticket can be verified after load balancing.
  The Kubernetes workload consumes this value only from the mounted
  `checkout-web-frame-ticket-key` Secret, never through a Secret-to-environment mapping.

Security controls include a fail-closed CSP, `frame-ancestors 'none'`, no
referrer, same-origin credentials, bounded proxy bodies/responses, redirect
blocking, short upstream timeouts, signed-token rejection, and strict static
path handling. The canonical authenticated API is `/v1/checkout-sessions`;
the `/api/checkout/sessions` spelling is intentionally browser-facing only.

The deployable process exposes `/health/startup`, `/health/live`, and
`/health/ready`. Readiness fails closed until an upstream API origin is explicitly
configured; the probes never claim that provider, certification, or production
acceptance gates have passed.

## Isolated provider SDK bootstrapping

Provider SDK code is never inserted into the checkout document. The only code
allowed to select an SDK is the server-side
`security/provider-sdk-allowlist.json`, which is version controlled and reviewed
like source. Each enabled entry pins all of the following:

- exact provider and checkout method ownership;
- exact SDK version and canonical HTTPS script URL;
- exact SHA-384 Subresource Integrity value;
- the `elmpay-isolated-provider-v1` adapter contract;
- the complete set of non-secret public configuration keys;
- explicit network and nested-frame origins; and
- owner, review expiry, and enablement state.

The checked-in allowlist intentionally contains no enabled provider SDKs until
the exact official adapter bytes and SRI digest have completed provider/security
review. This is a fail-closed provisioning state, not certification evidence.
Adding a provider requires a reviewed manifest change; no environment variable,
query parameter, browser global, checkout-session payload, or upstream API can
add or replace a script URL.

For an enabled method, the browser calls only the same-origin endpoint
`/api/checkout/sessions/{id}/provider-sdk-config?method=…&channel=…` using the
short-lived checkout authorization. The upstream response must contain exactly
`method`, `provider`, `sdkVersion`, and `publicParameters`. The web service
matches those values to the checked-in allowlist and rejects responses that
contain `scriptUrl`, `integrity`, secret-shaped keys, an unowned method, or an
unreviewed version. It then returns a 30-second HMAC-bound frame ticket. The
ticket binds method, policy version, random channel, expiry, and a digest of the
sanitized public configuration.
The proxy forwards both method and the random channel to edge. Edge independently binds that
channel to a durable authorization receipt after validating the checkout snapshot and provider
account; redirects, cross-origin targets, oversized responses, TLS downgrade and missing client
identity all fail closed.

The browser creates an iframe whose source is only the same-origin signed frame
endpoint. The iframe uses `sandbox="allow-scripts"` without
`allow-same-origin`, sends no referrer, grants no browser permissions, and has a
frame-specific CSP. The server-rendered frame is the sole place where the exact
allowlisted provider script URL appears; the tag carries both the per-response
CSP nonce and pinned SRI. Provider code therefore executes in an opaque origin
and cannot read the checkout session token, parent DOM, storage, or cookies.

Reviewed provider adapter bytes must expose an object named
`ElmPayIsolatedProviderSdk` with:

```text
integrationType = "elmpay-isolated-provider-v1"
initialize(configuration, container)
tokenize(context) -> opaque payment-method reference
handleAction({ action, context })
```

The parent retains the existing immutable `ElmPayPaymentMethodTokenizer` and
`ElmPayNextActionHandler` interfaces. Their adapters now communicate with the
frame only through a channel-bound RPC protocol. The parent accepts messages
only from the exact iframe `contentWindow` and the expected opaque origin; the
frame accepts messages only from its parent and verifies the signed
configuration digest before initialization. Redirect actions remain denied by
default. SDK load errors, malformed messages, integrity failures, unknown
methods, configuration mismatches, initialization failures, and handshake or
operation timeouts remove the iframe and reject the payment operation. None of
those conditions is mapped to payment success.

The Node test sources cover allowlist parsing, URL/integrity pinning, ticket
tampering and expiry, same-origin configuration, arbitrary URL injection,
sandbox flags, message source/origin binding, cleanup on timeout/error, and the
existing provider-handler API. External provider certification, browser UAT,
penetration assessment, and production acceptance remain separate evidence
gates.
