# Admin Web privileged-domain model

The module contains dependency-free Node.js domain code for two privileged UI
boundaries. `buildDiagnosticView` creates an immutable allow-listed read-only
projection, strips credentials and personal data, hashes trace/provider
references, and enforces tenant scope. `createApproval`/`decideApproval` enforce
tenant scope, optimistic versions, expiry, proposal digests, four-eyes approval,
phishing-resistant authentication, and chained audit digests.

This is the UI security/domain layer, not a claim that an IdP, durable audit
store, or production admin deployment has been verified.
