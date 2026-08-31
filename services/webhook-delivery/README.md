# Webhook delivery

`WebhookDeliveryService` leases tenant-scoped outbox records, re-resolves allowlisted HTTPS hosts to block SSRF/DNS rebinding, signs exact payload bytes, and classifies delivery into success, bounded retry, or durable dead letter. `DataSourceWebhookOutbox` supplies deduplicated enqueue, crash-expiring leases, retry scheduling and tenant RLS; signing keys support overlap rotation and are supplied from an external secret manager.

Production endpoint registration, replay approval workflows, external receiver acceptance, and network certification remain `NOT_RUN`.

The signing-secret lease client uses the shared bounded subscriber (128-byte hard limit), requires
one exact `application/octet-stream` content type and exact binding headers, and wipes its request,
response copy, and closeable response storage on success and failure. Access-token/HTTP-header
strings and JDK HTTP/TLS internal buffers remain outside explicit erasure control.
