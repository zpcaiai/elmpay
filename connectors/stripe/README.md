# Stripe connector boundary

This tracked boundary reserves the Stripe adapter. No API or webhook secret is present; implementation must use tokenized hosted fields, official SDK behavior, idempotency keys, raw-body webhook verification, and conservative outcome classification.
