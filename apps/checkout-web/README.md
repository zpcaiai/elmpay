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
  `ELMPAY_API_BASE_URL` without embedded credentials.

Security controls include a fail-closed CSP, `frame-ancestors 'none'`, no
referrer, same-origin credentials, bounded proxy bodies/responses, redirect
blocking, short upstream timeouts, signed-token rejection, and strict static
path handling. The canonical authenticated API is `/v1/checkout-sessions`;
the `/api/checkout/sessions` spelling is intentionally browser-facing only.
