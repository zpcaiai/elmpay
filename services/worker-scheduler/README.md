# Worker Scheduler boundary

This tracked boundary reserves bounded background work for queries, reconciliation, retention, certificate checks, and recovery. No deployable scheduler is claimed here; jobs require durable leases, tenant scope, idempotency, retry limits, and audit.
