# Worker Scheduler domain core

`FencedLeaseManager` implements exclusive leases with monotonically increasing
fencing tokens, expiry, renewal, and stale-worker rejection. `FencedJobRunner`
passes the token into every sink operation. `RetentionGate` binds a dry-run
digest to a versioned retention policy and enforces tenant scope, minimum age,
legal hold, and distinct requester/approver identities before deletion.

The included lease store is deterministic and useful for a single process. A
production deployment must supply equivalent atomic persistence and make every
downstream sink reject stale tokens; deployment readiness remains fail-closed
until that integration is verified.
