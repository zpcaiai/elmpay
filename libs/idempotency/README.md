# Idempotency boundary

This tracked boundary owns reusable idempotency semantics. Production implementation requires a durable tenant-scoped key, request digest, unique constraint, transactional result record, conflict behavior, expiry policy, and concurrency proof.
