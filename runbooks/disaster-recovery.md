# Disaster recovery

1. Open a DR incident and identify two distinct promotion approvers.
2. Prove the primary write fence is active; ambiguous primary state blocks
   promotion.
3. Measure replication lag against `platform/dr/plan.json`; lag above RPO blocks
   promotion.
4. Verify provider callback routing, secrets availability, time synchronization,
   ledger consistency, and rollback/failback commands in the standby region.
5. Promote, record actual RPO/RTO, run read-only reconciliation, then enable
   bounded traffic through the canary policy.
6. Fail back only after the former primary is rebuilt or fully reconciled and a
   second two-person approval is recorded.

Local configuration validation never closes the required external DR exercise
gate. Missing exercise receipts keep final release blocked.
