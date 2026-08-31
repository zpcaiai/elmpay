# Security boundary

This tracked boundary owns reusable security policy contracts. It must keep secrets in managed key systems, enforce deny-by-default authorization and tenant scope, and emit auditable decisions without becoming a side channel for sensitive data.

`BoundedHttpTransport.send(HttpClient, HttpRequest, int)` is the shared JDK HTTP response
boundary. It rejects ambiguous or oversized `Content-Length`, enforces the same limit while
streaming with wipe-on-growth buffers, bounds response header names/values, cancels
duplicate/failed/timed-out subscriptions, ignores callbacks after close, and
returns an `AutoCloseable` response whose owned body is wiped. Callers must close the response and
wipe every copy returned by `body()`. `WipeableFlatJson` strictly decodes UTF-8 into owned `char[]`
storage and decodes canonical Base64URL secrets without first creating secret-bearing `String`
values. KMS data-key results are also closeable and are closed by `EnvelopeEncryptionService`.

This is a best-effort managed-heap erasure boundary, not a proof of process-memory zero retention.
JDK HTTP/TLS/socket buffers, immutable `HttpHeaders`, access-token `String` values required by the
JDK Authorization-header API, cryptographic-provider internals, crash dumps, and copies made below
the Java API remain outside explicit erasure control.
