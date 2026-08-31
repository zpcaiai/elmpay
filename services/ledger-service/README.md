# Immutable ledger runtime

The ledger is a production-mode Java library executed by the deployable
`worker-scheduler` process.  It is not an HTTP service: catalogued financial
events are consumed from Kafka and the inbox marker, aggregate-revision fence,
posting-policy lookup, balanced journal entry and entries are committed in one
PostgreSQL transaction.

Runtime invariants are enforced by code and migrations:

- integer minor units and a single ISO-4217 currency per journal entry;
- equal debit and credit totals, tenant-scoped accounts and immutable postings;
- `(tenant, source_kind, source_id)` idempotency and append-only corrections;
- explicit, versioned tenant/project/provider/currency posting policies;
- an ordered event revision guard, so stale, duplicated or gapped money events
  cannot create an additional posting;
- TLS-verified PostgreSQL and Kafka connections with credentials supplied only
  through read-only mounted files.

The worker deliberately fails closed when accounts or posting policies have not
been provisioned by the governed onboarding path.  The migrations do not seed
merchant-specific accounting policy.

The implementation and repository tests are local engineering evidence only.
External ledger review, production data reconciliation, PCI/UAT, disaster
recovery and merchant acceptance remain separate evidence gates and are not
claimed by this README.
