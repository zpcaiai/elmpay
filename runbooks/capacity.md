# Capacity and cost response

Maintain at least 30 percent measured headroom for payment-path compute, database
connections, Kafka partitions, telemetry queues, and provider rate limits.

When the alert fires, separate demand growth from leaks, retry storms, provider
degradation, and telemetry backpressure. Apply bounded admission control before
queues become unbounded. Scaling must preserve PDB, zone spread, network policy,
and immutable image requirements. Record the forecast horizon, cost impact, and
rollback point; do not reduce redundancy or security controls to silence the
alert.
