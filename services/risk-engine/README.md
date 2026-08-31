# Risk Engine production runtime

`RiskEngineApplication` is the independently deployable B80–B83/B87 boundary. Its business
listener is TLS 1.3 with mandatory client certificates; health runs on a separate HTTP port.
`/v1/risk/nonces` issues a server-random, short-lived challenge and `/v1/risk/decisions` consumes
it exactly once. The nonce, caller SPIFFE identity, tenant, project, request ID and canonical
request digest are bound in PostgreSQL. Raw subject IDs are used only while decoding the mTLS
request; durable rows and events contain tenant-scoped subject digests.

The final serializable transaction consumes the nonce, detects idempotency digest conflicts,
locks the active rule set, stores the signal snapshot and model result, writes the immutable
decision, allocates a database-owned aggregate revision, and appends `risk.decision.v1` to the
shared outbox. The existing worker-scheduler relay publishes that outbox with leases and fencing.
A crash before commit leaves no partial decision or event; a retry after commit returns the same
decision for the same digest. Missing/expired signals, malformed/non-finite decimals, stale model
results, dependency timeouts and corrupt/missing rule sets can only produce `REVIEW` or `BLOCK`.

Signal and model dependencies are fixed-origin HTTPS services using separate mounted mTLS
identities, TLS 1.3, hostname verification, bounded streaming bodies, finite timeouts and no
redirects. Each production dependency hop has the governed fixed 100 ms timeout; overrides fail
closed. Responses have exact schemas and must bind tenant, project, request, request digest,
signal digest, version, expiry and content digest. Readiness is 503 unless PostgreSQL schema,
an unexpired activated rule capability, the signal service, and the model service are all ready.
Transport responses are explicitly closed and their mutable byte arrays are wiped; request bytes
and bounded-subscriber buffers are also wiped on success, timeout, oversize and error paths.
Immutable JSON strings and buffering owned inside the JDK HTTP/TLS implementation remain
garbage-collector managed, so this is not a claim of provable process-memory zero retention.

Rule-set and list/case mutations are exposed only on the same mTLS listener and authorized by a
read-only SPIFFE capability policy. `JdbcRiskControlPlane` requires independent certificate
identities, optimistic record versions, unexpired approvals and the mounted governance-policy
digest. Approval applies list/case effects and appends `risk.operation.applied.v1` in one
transaction. The legacy `RiskOperations` and Python/SQLite CLI remain development/reference
surfaces; they are not the production runtime.
Caller-policy entries bind every SPIFFE identity and capability to an explicit canonical
tenant/project pair; wildcard scopes and caller-supplied permissions are rejected.

`AdminRiskActionCommandConsumer` is the production bridge for approved admin `CASE_CLOSE`,
`LIST_ADD`, and `LIST_REMOVE` actions. A first serializable transaction durably claims the shared
command with a replica-specific worker ID, lease, attempt and monotonically increasing fence. A
second serializable transaction inserts the risk-owned operation/effect and audit/outbox event,
then writes the shared effect receipt and changes the command to `APPLIED` before one commit. A
crash before that commit leaves no domain effect; stale claims recover through `UNKNOWN`. An
uncertain commit is reconciled by the same idempotency key and immutable command/effect digests,
never by executing a different command. Expired approvals, SoD violations, stale fences,
non-digest targets, cross-project bindings, unsupported operations and policy-digest mismatches
fail closed. Readiness stays 503 until this consumer has completed a recent database cycle.

Production requires `ELMPAY_RISK_MODE=production`; credential, certificate, key, CA, caller-policy
and governance-policy inputs are absolute, bounded, read-only mounts. Kubernetes projected-secret
rotation symlinks are accepted only when their resolved target stays inside the configured mount.
Each environment key is bound to one exact `/var/run/secrets/elmpay/...` directory and filename;
arbitrary read-only local files are rejected. PostgreSQL pins each inspected CA/certificate/key
real path for one connection so a projected-secret rotation cannot change the driver input between
validation and use. The governance policy has the exact schema
`{"schemaVersion":1,"adminActionPolicyDigest":"<sha256>","validUntil":"<RFC3339>"}`; the
admin digest and expiry are independently checked when a domain command is applied.
The same governance expiry disables every direct rule and operation mutation; the process remains
available only for health diagnostics and fail-closed decision handling until governed policy is
reloaded.
The PostgreSQL URL is credential-free and query-free, and the JDBC driver is forced to
`sslmode=verify-full` with mounted client authentication. Production accepts only the exact
`elmpay_risk_engine` login and fixes `search_path` to `pg_catalog,public,pg_temp`. Before any
listener or consumer starts, `RiskRuntimeSchemaVerifier` rejects superuser, `BYPASSRLS`, role
membership, database `CREATE`/`TEMP`, application-schema access or ownership, relation ownership,
missing forced RLS, a non-exact tenant policy, missing required table or sequence privileges,
every extra privilege on its required tables/sequences, any mutation grant on another application
relation, and every executable application-schema `SECURITY DEFINER` routine outside the five
fenced admin-consumer APIs. Its successful result is also required for readiness. Workload and peer leaves
must have digital-signature key usage; every chain issuer and mounted trust authority must have
CA basic constraints plus `keyCertSign`. HMAC risk authentication and inline password/private-key
values are rejected.

The schema migration is `V102__risk_engine_runtime.sql`. It enables and forces RLS on tenant
tables, protects immutable snapshots/decisions/audit, enforces unique request and nonce replay
keys, and records four-eyes transitions. Runtime ACL changes are applied only through later
additive migrations; the checksum-bound V102 file is not rewritten. Deployment policy runs three replicas and permits only
PostgreSQL plus the fixed signal/model services; edge-gateway reaches the decision API through an
explicit `INTERNAL_API` route.

This code does not claim provider/IdP/WebAuthn certification, independent review, PCI/UAT,
penetration testing, production shadow/canary acceptance, or production evidence. Those remain
external evidence gates; repository certification remains `0/128 NOT_CERTIFIED` until real
review records exist.
