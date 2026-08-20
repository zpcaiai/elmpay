#!/usr/bin/env python3
"""Regenerate the API artefacts, check them for drift, or record the baseline."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.apigen import baseline_json, render_all  # noqa: E402

BASELINE = Path("contracts/api/openapi.baseline.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--record-baseline", action="store_true",
                        help="re-record the compatibility baseline; only legitimate when opening "
                             "a new major version")
    args = parser.parse_args()

    if args.record_baseline:
        path = ROOT / BASELINE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(baseline_json(ROOT), encoding="utf-8")
        print(f"recorded    {BASELINE}")
        return 0

    drifted = []
    for rel, content in sorted(render_all(ROOT).items()):
        path = ROOT / rel
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == content:
            print(f"up-to-date  {rel}")
        elif args.check:
            drifted.append(rel)
            print(f"DRIFTED     {rel}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"written     {rel}")
    if drifted:
        print(f"\n{len(drifted)} generated API artefact(s) drifted")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
