# Ledger Service boundary

This tracked boundary reserves the immutable double-entry ledger service. No deployable ledger is claimed here; implementation must enforce balanced postings, integer minor units, append-only correction, tenant scope, and transactionally durable audit evidence.
