# ElmPay client SDKs

These clients call server-authoritative checkout APIs. Retries are bounded and
only enabled for requests carrying an idempotency key. A mobile deep link or
browser return never means that payment succeeded; applications must retrieve
the verified server state.

All clients use the contract route `/v1/checkout-sessions` (hyphenated). The
slash-separated `/v1/checkout/sessions` route is not supported. Browser UI
traffic uses the distinct same-origin `/api/checkout/sessions` reverse proxy
with a signed checkout-session credential rather than a platform bearer token.

No SDK accepts or logs PAN, CVV, wallet plaintext tokens, API secrets, or full
request bodies.
