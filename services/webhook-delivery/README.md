# Webhook Delivery boundary

This tracked boundary reserves signed event delivery to business projects. No deployable delivery worker is claimed here; implementation must provide endpoint allowlists, bounded retries, dead letters, replay approval, key rotation, and tenant isolation.
