# Test-only launch inputs

`china-mvp-external-evidence.placeholder.json` is a completeness template for
the China mainland MVP. It contains temporary `PENDING_*` values for independent
review, WeChat/Alipay certification, PCI, penetration testing, UAT, production
Kubernetes/DR, shadow/canary, merchant acceptance, commercial readiness,
Go/No-Go and final release sign-off.

Validate its local shape with:

```bash
python3 tools/runtime/control.py test-evidence-template \
  --template testing/fixtures/china-mvp-external-evidence.placeholder.json
```

A successful command means only that every external owner has a field to fill.
It always reports `productionReleaseAllowed=false` and
`certificationStatus=NOT_CERTIFIED`. Do not copy this file to `evidence/`, rename
it to `review.json`, sign it, or supply it to the protected release environment.
Real evidence must be independently issued, current, release-bound and signed.
