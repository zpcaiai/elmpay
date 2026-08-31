# Admin Web privileged boundary

`admin-web` is a runnable Node.js 24 HTTPS boundary for privileged diagnostics
and digest-bound four-eyes approvals. It does not accept cookies, passwords,
static API keys, caller-provided permissions, or caller-provided
`phishingResistant` flags.

## Security model

- Corporate operator access is an ES256 `at+jwt` with an exact issuer,
  `admin-web` audience, `kid`, lifetime, subject, tenant, governed roles,
  `auth_time`, device posture and phishing-resistant `amr` claim.
- Every request uses a DPoP proof bound to method, canonical public URI, access
  token hash, embedded P-256 key thumbprint, a server nonce, proof `jti`, and a
  narrow time window. Nonces and proof replay keys are consumed atomically in
  PostgreSQL. Tokens are checked against a fresh, ES256-signed revocation
  snapshot on every request.
- Permissions are derived from `governance/authorization.json`; token claims
  cannot invent permissions. Tenant, object, permission, field projection,
  separation-of-duties, 15-minute approval expiry, optimistic versions, recent
  step-up, independent approvers and bounded JIT elevation all fail closed.
- Diagnostics expose an allow-listed projection only. Credentials, PAN/CVV,
  email, phone, unrestricted metadata and mutation links are excluded; trace
  and provider references are hashed.
- Production writes are disabled whenever PostgreSQL or the mTLS upstream is
  unavailable. A safe diagnostic snapshot may be served read-only for at most
  15 minutes; stale or absent snapshots fail closed.
- `APPROVED` is not a terminal claim: the same PostgreSQL decision transaction
  inserts a digest-bound `admin_action_dispatch` row and tenant scheduling
  signal. A bounded worker leases and fences each row, never calls the network
  before commit, reuses one idempotency key, queries receipts after a crash or
  unknown result, applies finite backoff, and persists only validated receipt
  digests. Expired, digest-mismatched, stale-fence, redirected, oversized, or
  unsupported actions fail closed.
- The production receiver is co-deployed with `edge-gateway`, but is isolated
  under `/internal/admin/*`. It authenticates `admin-web` from the TLS session
  with an exact SPIFFE URI SAN, TLS-client EKU, certificate validity and TLS 1.3;
  forwarded certificate/identity headers are rejected. Every dispatch carries
  the current worker, lease deadline and fencing token, and the receiver locks
  the matching `admin_action_dispatch` and `admin_approval` rows before it
  atomically enqueues an immutable, tenant/project-bound `admin_domain_command`.
  The edge receiver never updates risk, refund, or rollout owner tables.

## Production startup

Apply [`migrations/V018_019__admin_web_runtime.sql`](migrations/V018_019__admin_web_runtime.sql)
with the controlled migration job, grant the runtime role only the stated
tables/sequences, and then run:

```sh
npm start
```

Startup requires `ADMIN_RUNTIME_MODE=production` and all of these explicit
mounts/configurations:

- `ADMIN_PUBLIC_ORIGIN`, `ADMIN_LISTEN_HOST`, `ADMIN_PORT`
- `ADMIN_IDP_ISSUER`, `ADMIN_IDP_AUDIENCE=admin-web`
- `ADMIN_IDP_JWKS_FILE`, `ADMIN_IDP_REVOCATION_FILE`
- `ADMIN_AUTHORIZATION_FILE`, `ADMIN_ACTION_POLICY_FILE`
- `ADMIN_TLS_CERT_FILE`, `ADMIN_TLS_KEY_FILE`
- `ADMIN_PSQL_PATH`, `ADMIN_PG_SERVICE`, `ADMIN_PG_SERVICE_FILE`,
  `ADMIN_PG_ROOT_CA_FILE`
- `ADMIN_UPSTREAM_ORIGIN`, `ADMIN_UPSTREAM_CA_FILE`,
  `ADMIN_UPSTREAM_CERT_FILE`, `ADMIN_UPSTREAM_KEY_FILE`

Credential and policy files must be absolute, read-only (`mode & 0222 == 0`)
regular files. The image-layer `psql` executable must be root-owned when its
owner-write bit is set, executable, and never group/world writable; ordinary
root-owned mode `0755` is accepted. PostgreSQL uses a libpq
service file with `sslmode=verify-full`; inline database URLs and `PGPASSWORD`
are rejected. The HTTPS listener is TLS 1.3 only, has bounded headers/timeouts,
and exposes `/health/startup`, `/health/live`, and `/health/ready`.

The API consists of:

- `GET /auth/dpop-nonce`
- `GET /api/admin/diagnostics?tenantId=...&service=...`
- `POST /api/admin/approvals`
- `GET /api/admin/approvals/{id}?tenantId=...`
- `POST /api/admin/approvals/{id}/decisions?tenantId=...`

The upstream `/internal/admin/diagnostics` contract and upstream health are
called only through TLS 1.3 with a mounted CA and workload certificate, strict
timeouts, no redirects, bounded response bytes and an exact JSON shape. This
boundary additionally requires the upstream to advertise all four governed
action contracts before readiness, posts only to
`/internal/admin/actions/dispatches`, and reconciles uncertain outcomes through
`/internal/admin/actions/receipts/{idempotencyKey}`. Dispatch and receipt calls
also carry the exact tenant selector used solely to establish PostgreSQL RLS;
the selected row must still match the digest-bound approval and opaque
idempotency key.

The domain action consumers live in the owning payment-core, risk-engine and
worker-scheduler services; admin-web never executes business mutations. The
deployable ingress is
`apps/edge-gateway/src/main/java/com/elmpay/gateway/AdminActionHttpHandler.java`;
`JdbcAdminActionService` validates the persisted approval/fence and only
enqueues or queries a command. It advertises capabilities only on the strict-mTLS
listener and readiness remains false unless the ingress database role is a
non-superuser/non-`BYPASSRLS` role and the required FORCE-RLS approval,
dispatch, command, receipt, and diagnostic tables exist.

Apply this application's `V018_019__admin_web_runtime.sql`, edge gateway's
`V087_1__admin_action_effects.sql`, the risk runtime migration, and worker
scheduler's `V087_2__admin_rollout_effects.sql` through the ordered database
migrator before enabling dispatch. The edge workload must set
`ELMPAY_ADMIN_ACTIONS_ENABLED=true` and an exact
`ELMPAY_ADMIN_ACTION_EXPECTED_SPIFFE_ID`; it reuses the mounted verify-full
PostgreSQL mTLS identity and the gateway client-CA trust bundle. The dispatch
contract additionally binds `workerId`, `fencingToken` and `leaseUntil`.

The typed effects are deliberately narrow and run only in their owning
deployment:

- `CASE_CLOSE`, `LIST_ADD`, and `LIST_REMOVE` are consumed by `risk-engine`.
  That consumer revalidates the current governed policy and staged operation,
  then commits the typed risk effect, semantic outbox, immutable effect receipt,
  and command `APPLIED` state in one risk-owned transaction.
- `REFUND_OVERRIDE` is consumed by the payment owner co-deployed in
  `edge-gateway`. It can only move the immutable, digest-bound refund snapshot
  from `approval_pending` to `approved`; the refund action receipt, semantic
  outbox, immutable admin effect receipt, and command `APPLIED` state commit in
  one payment transaction, with no provider network call.
- `ROLLOUT_APPROVAL` is consumed by `worker-scheduler`. It records only a
  fence-, artifact-, project-, proposal-, and policy-bound internal stage
  approval together with its outbox/receipt/`APPLIED` state. It never advances a
  rollout and cannot substitute for signed release gates, observation windows,
  production canary evidence, or rollback authorization.

The queue leases one command at a time per tenant/consumer group with
monotonic fencing, bounded retry and stale-lease recovery. An owner appends
`admin_action_effect_receipt` in the same transaction as the domain mutation and
semantic outbox, immediately before the command becomes `APPLIED`. A crash
before commit leaves no receipt or partial effect; a lost response remains
`PENDING`, `RETRY`, or `UNKNOWN` and is reconciled through the tenant-scoped
receipt/status query without redispatching a new command. A newer fence rejects
a stale owner.

## Evidence boundary

The source and tests cover key/token rejection, DPoP binding and replay,
tenant/role/field scope, SoD, step-up, approval expiry and concurrency, RLS,
immutable audit, durable dispatch, crash/duplicate recovery, stale fencing,
receipt validation, typed domain binding, redaction, production config, health
and dependency degradation. Corporate IdP onboarding, authenticator attestation
metadata, independent human approval, penetration testing and production
deployment remain external evidence gates. This implementation does
not claim official IdP/WebAuthn or production certification; repository
certification remains `0/128 NOT_CERTIFIED` until those independent gates are
satisfied.
