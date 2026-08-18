#!/usr/bin/env python3
"""Run the governance test suite and emit a machine-readable summary.

``skipped_critical`` is reported separately from ordinary skips: the batch gate
rejects any completion whose critical tests were skipped, so the number has to
be produced by the runner rather than asserted by a human.
"""
from __future__ import annotations

import argparse
import json
import unittest
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Every governance test is treated as critical: none of them are optional, so a
# skip in any of them must block the batch rather than be silently tolerated.
CRITICAL_PREFIXES = ("test_",)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--log", help="also write the verbose runner log here")
    args = parser.parse_args()

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(ROOT / "tools" / "tests"), top_level_dir=str(ROOT))
    stream = StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)

    skipped_critical = sum(
        1 for case, _ in result.skipped
        if str(case).split(" ")[0].startswith(CRITICAL_PREFIXES)
        or "tools.tests." in str(case)
    )

    summary = {
        "run": result.testsRun,
        "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "failed": len(result.failures) + len(result.errors),
        "skipped": len(result.skipped),
        "skipped_critical": skipped_critical,
        "failures": [str(case) for case, _ in result.failures],
        "errors": [str(case) for case, _ in result.errors],
    }
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.log:
        log = ROOT / args.log
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(stream.getvalue(), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["failed"] == 0 and summary["skipped_critical"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
