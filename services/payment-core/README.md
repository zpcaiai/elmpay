# Payment Core

This Java module implements immutable payment-intent snapshots, tenant-scoped idempotency,
provider-call attempts, optimistic concurrency, deterministic routing, authorization/capture/void,
unknown-outcome querying and a transactional PostgreSQL outbox. Successful money states can only be
written from server-side provider results, verified provider events or reconciliation authority.
It stores PSP/wallet references and normalized digests, never PAN, CVV, or raw wallet tokens.

The checkout package binds each short-lived hosted session to its payment intent, tenant/project,
integer amount, currency, approved return route, device-context digest, expiry, key version, and
allowed methods. Its repository port supports a local in-memory implementation and a PostgreSQL
adapter at the gateway. Checkout success is a projection of the authoritative payment-intent state,
never a browser callback.

Production provider credentials and the Apple Pay PSP forwarder use dedicated TLS 1.3 client
contexts. Each context requires three explicit file paths: `<PREFIX>_MTLS_CLIENT_CERT_FILE`,
`<PREFIX>_MTLS_CLIENT_KEY_FILE`, and `<PREFIX>_MTLS_TRUST_BUNDLE_FILE`, where the prefix is
`ELMPAY_PROVIDER_CREDENTIAL` or `ELMPAY_APPLE_PAY_PSP`. Provider credentials additionally require
`ELMPAY_PROVIDER_CREDENTIAL_ACCESS_TOKEN_FILE`; all four values must resolve to the exact
`/var/run/secrets/elmpay/provider-credential-client/{tls.crt,tls.key,ca.crt,token}` projected
mount. Inline tokens, the old `_TOKEN_FILE`/`_TIMEOUT_MS` aliases, and arbitrary filesystem paths
are rejected. The loader accepts X.509 PEM chains and a
single PKCS#8 private key, checks validity/client-auth usage, cryptographically binds the private
key to the leaf certificate, and creates in-memory identity/trust stores without the JVM default
trust store. The former `<PREFIX>_MTLS=true` switch is rejected; missing or partial material stops
production startup. These local checks do not constitute provider or PCI certification.

The Apple Pay PSP identity is similarly pinned to
`/var/run/secrets/elmpay/apple-pay-psp-client/{tls.crt,tls.key,ca.crt}`. Its bearer credential is
not a static mount: it comes from the already tenant/account/version-bound short-lived provider
credential lease and is checked again before every PSP forwarding call.

The credential-gateway and Apple Pay broker clients pin TLS 1.3 with HTTPS endpoint
identification, reject redirects, require one exact `application/json` response content type, use
the shared bounded response subscriber, and close/wipe request and response byte arrays on every
terminal path. Credential and KMS secret JSON values are held in wipeable character arrays and
decoded directly into owned bytes rather than immutable secret-bearing JSON strings. Bearer-token
and Authorization-header strings plus JDK/TLS/provider-internal buffers remain garbage-collector
managed and are not claimed to be synchronously erasable.
