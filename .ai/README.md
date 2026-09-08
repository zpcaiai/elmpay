# `.ai` evidence workflow

`rebaseline.py` is the only supported **evidence mutation** entry point in this directory. It does
not interpret prose or implementation presence as completion and it never creates an independent
review attestation. `implementation_audit.py` is read-only: it inventories code, tests and
migrations for B00-B127. Inventory is not execution; pass `--verify` to run the declared local
checks. Both modes always keep certification separate.

## Commands

```bash
python3 .ai/rebaseline.py --help
python3 .ai/rebaseline.py scaffold --from B36 --to B127 --dry-run
python3 .ai/rebaseline.py scaffold --from B36 --to B127
python3 .ai/rebaseline.py status --from B00 --to B127
python3 .ai/rebaseline.py migrate-shards --from B00 --to B127 --shards 4 --dry-run
python3 .ai/rebaseline.py migrate-shards --from B00 --to B127 --shards 4
python3 .ai/rebaseline.py resume --from B00 --to B127 --launch-window-seconds 300
python3 .ai/rebaseline.py reset --dry-run
python3 .ai/implementation_audit.py
python3 .ai/implementation_audit.py --json
python3 .ai/implementation_audit.py --verify --json
```

The default implementation audit reports inventory only and cannot emit an implementation pass.
An `--verify` pass means its declared repository-local code/test/control commands succeeded; it
does not change evidence, certified batch counts, release gates or independent-review requirements.

`scaffold` closes the B36-B127 orchestration gap by deriving each batch's plan,
command spec, artifact manifest and traceability from the package manifest,
implementation inventory, test matrix and external-gate policy. It never emits
`commands.ndjson`, `review.json`, completion files, signatures or approvals. It
diagnoses the entire requested range before the first write, is byte-idempotent,
and refuses to overwrite a non-identical input. A live resume state must be
explicitly reset before a non-dry scaffold run.

`migrate-shards` validates the entire requested range before its first write. A canonical family
contains exact, contiguous `1..N` negative-control shards and exact `1..N` test shards followed by
one merge. Partial, duplicate, mixed-denominator, noncanonical, or cross-batch input is rejected.

`resume` records one transactional command slice at a time. Local state is atomically stored under
the Git-ignored `.ai/.state/` directory and is bound to the real repository path, Git HEAD,
manifest, range, and every command specification. A stale binding is never auto-healed. The launch
window controls whether another slice starts; a running slice is allowed to finish safely.

## Completion boundary

Successful commands are not approval. Before traceability or completion can be finalized,
`evidence/<batch>/review.json` must be a Git-tracked, batch-contained approval from the configured
independent reviewer. It binds the current HEAD, manifest, command spec, prospective finalized
traceability, artifact manifest, and exact artifact path-to-SHA-256 map. Missing or stale review
returns `review-blocked` and leaves traceability and completion unchanged.

Completion replacement is atomic. Drift in HEAD, review bytes, trace, artifacts, or dependency
completions restores the prior marker or removes the new marker. A final orchestrator rejection has
the same rollback behavior.

The former `rebaseline-slices.py`, `rebaseline2.py`, `rebaseline3.py`, and stale progress handoff
are preserved under `_to_delete/legacy-ai-20260820/` for forensic recovery only. They are ignored by
Git and must not be executed.
