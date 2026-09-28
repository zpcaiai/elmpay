# External evidence gates

This runbook describes the boundary between repository implementation and
external certification. The repository does not create a review approval,
provider certificate, production observation, QSA/ASV report, UAT sign-off,
penetration report, DR exercise result, canary observation or merchant
acceptance.

## Verify a supplied bundle

Obtain the release-bound bundle and verifier trust material from the independent
party, outside this checkout. Then run:

```sh
python3 tools/runtime/control.py external-evidence \
  --bundle /secure/external-evidence.json \
  --trust /secure/external-trust.json \
  --manifest /secure/release.json
```

The verifier requires all categories in
`platform/compliance/external-evidence-policy.json`. Every record must be
independently signed, bound to the exact release commit/artifact/images, have a
fresh non-expired observation, and satisfy its measured semantic controls.
Missing, stale, unsigned, locally trusted, same-person or threshold-violating
records are blocked. The command never writes evidence.

## Release decision

Pass the same bundle and trust file to `go-no-go` with the shadow, canary,
capacity and operational inputs. Omitting either external input is an explicit
block. A local pass proves only that supplied external material is structurally
and cryptographically consistent; it does not itself grant certification.

Read the current completed-batch count from `scripts/batch.py status`; do not
substitute that local progress count for certification. Keep release status
`NOT_CERTIFIED` until the named human reviewer and external authorities have
supplied their real, independently verifiable artifacts and the release gate
passes. Do not copy synthetic test fixtures into `evidence/B00`.
