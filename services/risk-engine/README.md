# Risk Engine domain core

This module implements a deterministic, tenant-scoped risk decision core. Every
decision binds the rule-set digest and version, signal version, model version,
reason codes, degradation state, and decision time. Missing/stale signals and
model failures can never silently approve: they route to manual review.

`RiskOperations` supplies optimistic concurrency, four-eyes approval, tenant
isolation, expiry, and a hash-chained audit log for case closure and list changes.
The module deliberately does not claim an external signal feed, durable database,
or production deployment; those remain release-time integration gates.
