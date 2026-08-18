#!/usr/bin/env python3
"""Batch orchestration CLI backed by the in-repository implementation.

    scripts/batch.py status
    scripts/batch.py ready
    scripts/batch.py validate B03
    scripts/batch.py release
    scripts/batch.py crosscheck        # compare against the vendored orchestrator

``crosscheck`` is the interesting one: it runs the vendored
``.payment-platform/skill-package/scripts/orchestrate.py`` and asserts that both
implementations agree on the completed set, the ready set and every batch's
validity. A disagreement is reported as a failure rather than silently resolved
in favour of either side.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.orchestration import Programme  # noqa: E402

UPSTREAM = ".payment-platform/skill-package/scripts/orchestrate.py"


def upstream(*args: str) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, UPSTREAM, *args, "--repo", "."],
                          cwd=ROOT, text=True, capture_output=True)
    return proc.returncode, proc.stdout.strip()


def crosscheck(programme: Programme) -> int:
    mismatches: list[str] = []

    _, raw_status = upstream("status")
    theirs = json.loads(raw_status)
    ours = programme.status()
    for key in ("completed", "total", "remaining", "ready"):
        if theirs[key] != ours[key]:
            mismatches.append(f"status.{key}: upstream={theirs[key]!r} local={ours[key]!r}")
    print(f"status  upstream={theirs} local={ours}")

    _, raw_ready = upstream("ready")
    upstream_ready = [line for line in raw_ready.splitlines() if line.strip()]
    if upstream_ready != ours["ready"]:
        mismatches.append(f"ready: upstream={upstream_ready} local={ours['ready']}")

    cache: dict[str, bool] = {}
    checked = 0
    for batch in programme.order:
        local_valid = programme.valid(batch, cache)
        # Only batches with a completion file can plausibly be valid; validating
        # all 128 upstream would re-hash the tree 128 times for no information.
        if not programme.completion_path(batch).is_file() and not local_valid:
            continue
        code, _ = upstream("validate", batch)
        checked += 1
        if (code == 0) != local_valid:
            mismatches.append(f"validate {batch}: upstream_ok={code == 0} local_ok={local_valid}")
    print(f"cross-checked {checked} batch(es) individually")

    print(f"\nmismatches={len(mismatches)}")
    for mismatch in mismatches:
        print(f"  MISMATCH: {mismatch}")
    return 0 if not mismatches else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["status", "ready", "validate", "release", "crosscheck",
                                            "graph"])
    parser.add_argument("batch", nargs="?")
    args = parser.parse_args()
    programme = Programme(ROOT)

    if args.command == "status":
        print(json.dumps(programme.status(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "ready":
        print("\n".join(programme.ready()))
        return 0
    if args.command == "validate":
        if not args.batch:
            print("validate requires a batch id", file=sys.stderr)
            return 3
        problems = programme.problems(args.batch)
        deps = [d for d in programme.dependencies(args.batch) if not programme.valid(d)]
        problems += [f"dependency evidence is invalid: {d}" for d in deps]
        print(json.dumps({"batch": args.batch, "valid": not problems, "problems": problems},
                         ensure_ascii=False, indent=2))
        return 0 if not problems else 2
    if args.command == "release":
        result = programme.release_ready()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["release_ready"] else 2
    if args.command == "graph":
        print(json.dumps({"batches": len(programme.batches),
                          "cycles": programme.cycles(),
                          "unknown_dependencies": programme.unknown_dependencies(),
                          "topologically_sorted": programme.manifest_is_topologically_sorted()},
                         ensure_ascii=False, indent=2))
        return 0 if not programme.cycles() and not programme.unknown_dependencies() else 2
    return crosscheck(programme)


if __name__ == "__main__":
    raise SystemExit(main())
