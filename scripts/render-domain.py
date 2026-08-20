#!/usr/bin/env python3
"""Regenerate the PostgreSQL schema from the domain model, or check for drift."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.domaingen import render_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
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
        print(f"\n{len(drifted)} generated schema file(s) drifted")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
