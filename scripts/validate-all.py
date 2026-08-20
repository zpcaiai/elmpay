#!/usr/bin/env python3
"""Validate every batch that claims completion, and fail if any does not.

``orchestrate.py status`` prints a number and exits 0 whatever that number is,
so a pipeline that only runs `status` stays green while every batch silently
un-completes. This script is the check that notices, and it is wired into CI as
part of the evidence-archive stage.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.orchestration import Programme  # noqa: E402


def main() -> int:
    programme = Programme(ROOT)
    claimed = [b for b in programme.order if programme.completion_path(b).is_file()]
    if not claimed:
        print("no batch claims completion", file=sys.stderr)
        return 3

    failed: dict[str, list[str]] = {}
    for batch in claimed:
        problems = programme.problems(batch)
        deps = [d for d in programme.dependencies(batch) if not programme.valid(d)]
        problems += [f"dependency evidence is invalid: {d}" for d in deps]
        print(f"  [{'OK ' if not problems else 'FAIL'}] {batch}")
        if problems:
            failed[batch] = problems

    print(json.dumps({"claimed": len(claimed), "valid": len(claimed) - len(failed),
                      "failed": failed}, ensure_ascii=False, indent=2))
    if failed:
        print(f"\n{len(failed)} batch(es) claim completion but do not validate", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
