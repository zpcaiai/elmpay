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
