# Shadow, canary, and rollback

1. Run the candidate in shadow mode with outbound side effects disabled.
2. Compare request coverage, action, amount, currency, and reason codes. Any
   candidate side effect, missing record, or semantic mismatch fails the gate.
3. Obtain fresh release-manager and security approvals bound to the exact
   commit, artifact, and image digests.
4. Advance only through the stages in `platform/rollout/policy.json`. At each
   stage evaluate errors, p99 latency, authorization rate, ledger mismatch,
   duplicate effects, and critical security events.
5. An auto-stop reason immediately routes traffic to the previous digest,
   freezes advancement, and starts reconciliation.
6. Do not resume from the stopped percentage; create a new release binding and
   repeat shadow validation.
