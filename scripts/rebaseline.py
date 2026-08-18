#!/usr/bin/env python3
"""Re-issue evidence for every already-completed batch, in dependency order.

A later batch may legitimately change a file that an earlier batch listed as an
artefact (a shared validator gains a rule, a test file grows). The batch gate
compares artefact digests at validation time, so the earlier batch's evidence
must be re-produced against the new commit — otherwise the programme would
either drift silently or freeze all shared code after B00.

Order matters: dependency completion digests are embedded in dependents, so
parents are always re-issued first.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads(
    (ROOT / ".payment-platform/skill-package/manifest.json").read_text(encoding="utf-8"))
ORDER = [b["id"] for b in MANIFEST["batches"]]


def already_valid(batch: str) -> bool:
    proc = subprocess.run([sys.executable, ".payment-platform/skill-package/scripts/orchestrate.py",
                           "validate", batch, "--repo", "."],
                          cwd=ROOT, text=True, capture_output=True)
    return proc.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true",
                        help="re-issue evidence even for batches that still validate")
    args = parser.parse_args()

    done = [b for b in ORDER if (ROOT / "evidence" / "completion" / f"{b}.json").is_file()]
    if not done:
        print("no completed batches to re-baseline")
        return 0

    if not args.force:
        stale = []
        for batch in done:
            if already_valid(batch):
                print(f"[skip ] {batch} still validates against the current working tree")
            else:
                print(f"[stale] {batch} needs re-issued evidence")
                stale.append(batch)
        done = stale
        if not done:
            print("\nnothing to re-baseline")
            return 0

    print(f"\nre-baselining {len(done)} batch(es): {', '.join(done)}\n")
    for batch in done:
        print(f"===== {batch} =====")
        proc = subprocess.run([sys.executable, "scripts/finish-batch.py", batch],
                              cwd=ROOT, text=True, capture_output=True)
        print(proc.stdout + proc.stderr)
        if proc.returncode != 0:
            print(f"re-baseline failed at {batch}")
            return proc.returncode
    proc = subprocess.run([sys.executable,
                           ".payment-platform/skill-package/scripts/orchestrate.py",
                           "status", "--repo", "."], cwd=ROOT, text=True, capture_output=True)
    print(proc.stdout + proc.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
