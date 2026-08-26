# Incident response

## SLO fast burn

1. Declare an incident, record the affected tenant/region and freeze releases.
2. Compare provider, edge, payment-core, risk, ledger, and webhook SLIs without
   copying payment credentials or personal data into the incident channel.
3. If the candidate is active, invoke the rollout auto-stop and verify traffic
   returned to the last digest-pinned version.
4. Reconcile payment state and ledger effects before replaying any command.
5. Require incident commander approval before unfreezing; attach independent
   telemetry and reconciliation references to the incident record.

## Stale fencing token

1. Stop the affected job class and preserve scheduler lease/audit logs.
2. Confirm the sink rejected every token lower than its recorded maximum.
3. Reconcile side effects by idempotency key; never replay from log position
   alone.
4. Restore scheduling only after the durable lease store and sink agree on the
   current token.

## Telemetry backlog

1. Confirm collector memory and queue saturation without disabling redaction.
2. Shed low-priority debug telemetry before security/audit streams.
3. Restore the mTLS exporter path and verify queued data age and loss counters.
4. Escalate if the security stream exceeds its documented retention buffer.

## Evidence preservation

Export immutable event identifiers, canonical digests, and trusted timestamps.
Do not export PAN, CVV, access tokens, raw authorization headers, or customer
contact data. Record custody transfers and the hash of every exported bundle.
