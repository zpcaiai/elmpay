# Worker Scheduler runtime

`FencedLeaseManager` implements exclusive leases with monotonically increasing
fencing tokens, expiry, renewal, and stale-worker rejection. `FencedJobRunner`
passes the token into every sink operation. `RetentionGate` binds a dry-run
digest to a versioned retention policy and enforces tenant scope, minimum age,
legal hold, and distinct requester/approver identities before deletion.

`WorkerSchedulerApplication` is the production process entrypoint. It validates
the required PostgreSQL schema before startup, enumerates a bounded active
tenant/project work set, relays the transactional outbox to TLS/mTLS Kafka,
updates the payment timeline, drains durable subscription/dunning queues,
creates bounded daily tenant/provider reconciliation snapshots, and maintains
future archive partitions. Once per unique tenant in the bounded scope page it also leases the
latest durable audit root, obtains and verifies an independently signed Ed25519 timestamp receipt,
and drains at most one business-webhook delivery with a short-lived signing-secret lease. It also
consumes only the `ROLLOUT` group of the
leased/fenced `admin_domain_command` queue. That consumer verifies the current
read-only admin policy binding and immutable project/proposal/artifact/fence
facts, then records an internal rollout stage approval, semantic outbox event,
immutable effect receipt, and command `APPLIED` state in one transaction. It
does not advance the rollout or claim production approval. A stage failure is
isolated from the other
stages, but readiness expires unless a complete cycle succeeds. The process
exposes only `/health/startup`, `/health/live`, and `/health/ready` on its
dedicated health listener and shuts down its scheduler and Kafka producer with
bounded waits.

Production configuration is intentionally explicit. Database and Kafka
passwords come from mounted files; PostgreSQL uses `verify-full` with a mounted
CA and client certificate/private key, and startup rejects a superuser or
`BYPASSRLS` database role. Cross-tenant work discovery is limited to a bounded
`SECURITY DEFINER` function that returns only active tenant/project identifiers;
startup requires its explicit `elmpay_worker` execute grant before entering
tenant-scoped RLS transactions. The JDBC URL cannot contain credentials, query,
fragment, or TLS overrides and requires one explicit host, port, and database.
Every new connection revalidates bounded read-only password/CA/certificate/key
files; only an in-parent Kubernetes `..data` symlink rotation is accepted and
the verified target is pinned for that connection. The worker additionally
requires `ELMPAY_ADMIN_ACTION_POLICY_BINDING_FILE`,
`ELMPAY_ADMIN_COMMAND_MAX_PER_CYCLE`, and
`ELMPAY_ADMIN_COMMAND_LEASE_TTL`; an expired or mismatched governance binding
fails the owner command and closes readiness. Startup verifies that the worker
role can mutate only its queue projection, rollout approval, revision, and
outbox tables and has no `SELECT`, `INSERT`, `UPDATE`, or `DELETE` privilege on
refund or risk-owned tables. Kafka uses PKCS12 client and trust stores,
TLS 1.3, hostname verification, idempotent publishing, `acks=all`, and a bounded
ACK deadline. A dedicated ledger consumer uses the same TLS 1.3 identity with
`read_committed`, manual offsets, a single governed topic, exact unique envelope
headers, and aggregate-key ordering. It commits an offset only after the durable
inbox/revision guard/ledger transaction reports APPLIED or DUPLICATE; BUSY,
schema errors, missing posting policies and revision gaps rewind without commit.
`EventDeliverySettings`, `PaymentTimelineProjectionSettings`, and
`WorkerSchedulerSettings` reject missing or unbounded values. Database outbox
rows are marked published only after the broker ACK; a crash between those two
steps is an expected duplicate and consumers must use the durable inbox.

Audit timestamping is mandatory in the production composition and uses the exact
`/var/run/secrets/elmpay/audit-timestamp-client` projected mount. The environment must bind
`ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_MTLS_CLIENT_CERT_FILE`,
`ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_MTLS_CLIENT_KEY_FILE`,
`ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_MTLS_TRUST_BUNDLE_FILE`,
`ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_ACCESS_TOKEN_FILE`, and
`ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_RECEIPT_PUBLIC_KEY_FILE` to `tls.crt`, `tls.key`, `ca.crt`,
`token`, and `receipt-public-key.pem` in that mount. It also requires the exact HTTPS
`ELMPAY_AUDIT_TIMESTAMP_AUTHORITY_ENDPOINT` and `ELMPAY_AUDIT_ANCHOR_WORKER_ID`; bounded timeout,
lease, retry, and clock-skew values have safe defaults and may be tightened with their documented
`*_MILLISECONDS` variables.

Webhook signing-secret resolution is likewise mandatory and uses the exact
`/var/run/secrets/elmpay/webhook-signing-client/{tls.crt,tls.key,ca.crt,token}` mount through the
four `ELMPAY_WEBHOOK_SIGNING_SECRET_*_FILE` variables plus the exact HTTPS
`ELMPAY_WEBHOOK_SIGNING_SECRET_ENDPOINT`. Delivery timeouts, lease, and retry bounds use the
`ELMPAY_WEBHOOK_DELIVERY_*_MILLISECONDS` variables. Both clients pin TLS 1.3, HTTPS hostname
verification, and no redirects; validate mounted mTLS/key-use/trust material and rotating token
before startup; stream responses through a hard bound; and close/wipe application-owned request,
response, signature, and secret buffers. The JDK requires immutable Authorization-header Strings
and retains internal TLS/socket buffers outside the synchronous erasure boundary. A tenant with no
active endpoint and no active signing key is explicitly idle; a partial configuration is an error.
Any audit or webhook stage failure makes the latest cycle unsuccessful and immediately closes
readiness while leaving unrelated bounded stages isolated.

Reconciliation is round-robin bounded per tenant and provider. Its cutoff is
the end of the previous UTC business day plus the configured not-before delay,
so all replicas derive the same durable identity. The repeatable-read snapshot
binds semantic payment/refund events, their immutable ledger postings, and
provider/bank statement rows into a canonical manifest. Daily jobs use database
leases and fencing, explicitly recover expired/`UNKNOWN` work, and replay an
existing completed run. Missing external sources or an empty snapshot are
never synthesized: all four sources must be non-empty until an independently signed zero-period
contract exists. A missing source becomes a fenced durable `MISSING_SOURCE` cursor failure,
does not advance the business date, and prevents a fresh readiness success.
The durable schedule cursor keeps the oldest incomplete provider day across
replica competition and restarts and advances exactly once after completion.
It is created only for a tenant with a governed active production provider account and
at least one governed capability, and starts at the oldest eligible immutable
semantic-event or statement-row date rather than silently dropping a backlog.

`FencedLeaseManager` remains a deterministic single-process reference for
domain tests. The production runtime does not use it as distributed consensus:
outbox/inbox, timeline, billing, reconciliation, and partition operations use
PostgreSQL row locks, unique identities, advisory locks, leases, or monotonic
fencing at their own durable commit boundary.

The scheduler does not synthesize provider statements, bank files, business
order facts, archive receipts, or certification evidence. Reconciliation and
archive deletion do not treat missing authenticated external inputs as a match;
the runtime never treats an empty or self-reported snapshot as proof.
An internally recorded rollout approval is not external human acceptance,
production Kubernetes or multi-region evidence, shadow/canary acceptance, or a
certification result.
