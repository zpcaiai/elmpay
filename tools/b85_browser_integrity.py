#!/usr/bin/env python3
"""Executable B85 checkout script/page integrity gate."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.browser_integrity import validate_script_manifest  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ELMPay B85 browser integrity gate")
    parser.add_argument("--public-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    arguments = parser.parse_args(argv)
    report = validate_script_manifest(arguments.public_root, arguments.manifest)
    output = {**asdict(report), "certificationStatus": "NOT_CERTIFIED"}
    sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
    return 0 if report.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
