# Reconciliation service boundary

This module owns bounded provider/bank statement ingestion, deterministic four-source matching,
durable reconciliation runs, exception workflow, and signed financial-report primitives. The
deployable reconciliation entrypoint is the `worker-scheduler` process; the module is not a
separate network listener.

Statement intake accepts an exact five-column UTF-8 CSV schema. Amounts are positive integer
minor units, event types are `CAPTURE` or `REFUND`, provider sources are a governed provider name,
and bank sources are `provider:account`. The raw file and rows are append-only and bound to a
parser version, content SHA-256, tenant, source kind, provider, and ingestion time. No statement is
synthesized when a provider or bank feed is absent.

For each tenant/provider/UTC business day the worker creates one repeatable-read snapshot at a
stable delayed cutoff. BUSINESS facts come only from catalog `payment_intent.captured` and
`refund.succeeded` events; PLATFORM facts come from the corresponding balanced immutable ledger
transactions; PROVIDER and BANK facts come from ingested statement rows. Raw business order
references are converted to SHA-256 before snapshot persistence. Cross-project ambiguity, empty
snapshots, a missing one of the four independent sources, unknown providers, invalid money,
future cutoffs, source tampering, and manifest drift fail closed. Until an independently signed
zero-transaction-period contract is available, every source must contribute at least one fact.

Snapshot rows and canonical manifests are immutable and tenant-RLS protected. A daily job has a
durable input identity, monotonically increasing fencing token, database-clock lease bounded to one
hour, and explicit `unknown` state for an uncertain database outcome. A database trigger permits
only a canonical bound `queued` insertion; expired `running`, `failed`, and `unknown` jobs can be
reclaimed, while a completed job replays its durable result without writing a second run.
An RLS-protected schedule cursor starts at the oldest immutable source date and advances exactly
one business day only after an exact, digest-bound completed `recon_run`, so a direct SQL caller,
UTC day change, or process restart cannot skip an old failure.
Missing-source and runtime failures remain on that same date and update a fenced durable safe
error code/digest; exception messages and source data are never persisted in the cursor.
The first cursor date is derived from the oldest eligible immutable semantic event or statement
row, and providers without an active production account plus configured capability are not
scheduled.
Multiple legitimate partial facts are summed; an identical source-record digest is treated as a
duplicate rather than assuming every source must contain exactly one row.

This code is not provider/bank delivery evidence, independent review, merchant acceptance,
production deployment, or certification evidence. Those gates remain external and must not be
inferred from a local snapshot or test.
