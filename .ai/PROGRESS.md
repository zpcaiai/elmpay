# elmpay live implementation status

Snapshot: 2026-08-26, Asia/Shanghai. This is an implementation handoff, not completion evidence.
Use the live commands below instead of treating this document as an approval.

## Implemented repository-local runtime

- The vendored package still verifies as 128 batches and 65 skills. The declared Java/Node
  modules now contain production source and automated tests instead of README-only boundaries.
- B32-B36 now have a deployable Payment Intent/attempt core: immutable integer-money snapshots,
  deterministic routing, external token references, provider attempt reservations, optimistic
  concurrency, authorization/capture/void/query flows, PostgreSQL RLS, append-only audit/outbox,
  checksum-bound migration and an authenticated/rate-limited HTTP gateway. The local provider is
  available only behind the explicit `ELMPAY_ENABLE_LOCAL_SANDBOX=true` flag.
- B37-B55 contain provider HTTP/JCA implementations and durable webhook inbox/delivery paths for
  WeChat Pay, Alipay, Stripe, PayPal and Apple Pay-via-PSP boundaries. Missing live credentials or
  attribution fail closed.
- B56-B79 contain hosted checkout, signed sessions/links, server/mobile SDKs, refund/dispute,
  mandate/subscription/dunning, immutable double-entry ledger, statement ingestion,
  reconciliation and signed finance-reporting logic.
- B80-B127 contain versioned risk/case/four-eyes controls, scheduler fencing and retention,
  redacted admin diagnostics, Kubernetes/GitOps/identity policies, OTel/SLO/SIEM/DR/rollout/
  compliance controls, attack/scale tests and fail-closed release/Go-No-Go CLIs.
- `.ai/implementation_audit.py` inventories the implementation separately from certification.
  Inventory alone reports `implementation_surface=NOT_RUN`; only `--verify` can report a local
  implementation pass after executing the declared code, test and policy checks. It always keeps
  `certification_status=NOT_CERTIFIED` and never writes evidence.

## Certification boundary remains unchanged

- `scripts/batch.py status` remains authoritative for certified batch state. No independent human
  `review.json` approvals were created, no completion marker was fabricated, and no non-dry
  rebaseline was run on behalf of a reviewer.
- Repository-local tests do not prove PSP sandbox/live certification, production Kubernetes or
  multi-region DR, real OTel/SIEM ingestion, PCI/QSA/ASV/legal/finance/UAT approval, penetration
  testing, merchant acceptance, production shadow/canary, or public SDK-store releases.
- Until those exact external artifacts exist, release and Go/No-Go controls must remain blocked.

## Live verification

```bash
make skills-verify
python3 .ai/implementation_audit.py --verify --json
./gradlew --no-daemon test
python3 -m unittest discover -s testing -p 'test_*.py' -v
python3 tools/runtime/control.py validate
python3 scripts/batch.py status
python3 scripts/batch.py crosscheck
```

`.ai/rebaseline.py` remains the sole supported evidence replay workflow for batches that have
command specifications. Run it only after the implementation commit is final. Each batch will
stop at `review-blocked` until the configured independent reviewer supplies a tracked attestation
bound to the exact commit and artifact hashes.
