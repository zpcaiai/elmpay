# Webhook ingress

`WebhookIngressService` selects a provider verifier, authenticates the exact raw body before any database access, rejects raw card fields, and only then writes the verified event through `DataSourceWebhookInbox`. The PostgreSQL migration provides tenant RLS, a provider-event unique constraint, raw/canonical payloads, digests, and asynchronous processing state.

HTTP routing and deployment wiring are intentionally left to the edge service; provider sandbox callbacks remain `NOT_RUN`.
