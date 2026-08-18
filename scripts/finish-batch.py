#!/usr/bin/env python3
"""Produce (or re-produce) a batch's evidence and completion file, then validate.

    scripts/finish-batch.py B01

Steps, in order, all against the current working tree and the current git HEAD:

1. execute ``evidence/<batch>/commands.spec.json`` and record every command;
2. read the machine-readable test summary the spec produced;
3. regenerate ``evidence/completion/<batch>.json`` from real digests;
4. run the batch orchestrator's own validator.

Re-running this for an already completed batch is the supported way to
*re-baseline* it after a later batch legitimately modified one of its
artefacts: evidence is bound to a commit, so when the code moves the evidence
has to move with it (see docs/EVIDENCE.md).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ".payment-platform/skill-package/scripts/orchestrate.py"


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("batch")
    parser.add_argument("--accepted-findings", type=int, default=0)
    args = parser.parse_args()
    batch = args.batch
    base = ROOT / "evidence" / batch

    spec = base / "commands.spec.json"
    artifacts = base / "artifacts.json"
    for path in (spec, artifacts):
        if not path.is_file():
            print(f"missing required input: {path.relative_to(ROOT)}")
            return 3

    step = run([sys.executable, "scripts/record-commands.py", batch,
                "--spec", str(spec.relative_to(ROOT))])
    print(step.stdout + step.stderr)
    if step.returncode != 0:
        print(f"[{batch}] recorded commands did not all match their expected exit codes")
        return 2

    summary_path = base / "test-results" / "summary.json"
    if not summary_path.is_file():
        print(f"[{batch}] the command spec must produce {summary_path.relative_to(ROOT)}")
        return 2
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary["failed"] or summary["skipped_critical"]:
        print(f"[{batch}] test summary is not clean: {summary}")
        return 2

    records = [json.loads(line) for line in
               (base / "commands.ndjson").read_text(encoding="utf-8").splitlines() if line.strip()]
    started, completed = records[0]["timestamp"], records[-1]["timestamp"]

    step = run([sys.executable, "scripts/make-completion.py", batch,
                "--artifacts", str(artifacts.relative_to(ROOT)),
                "--started-at", started, "--completed-at", completed,
                "--tests-passed", str(summary["passed"]),
                "--accepted-findings", str(args.accepted_findings)])
    print(step.stdout + step.stderr)
    if step.returncode != 0:
        return 2

    step = run([sys.executable, ORCHESTRATOR, "validate", batch, "--repo", "."])
    print(step.stdout + step.stderr)
    return 0 if step.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
