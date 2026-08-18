#!/usr/bin/env python3
"""Execute a batch's evidence commands and record them verifiably.

Every command is really executed; its exit code, duration, output digest and
truncated tail are appended to ``evidence/<BATCH>/commands.ndjson`` in the shape
the batch orchestrator validates (timestamp, command, exit_code).

Long specs can be recorded in slices so that each slice fits inside a
constrained execution window:

    scripts/record-commands.py B02 --spec evidence/B02/commands.spec.json --range 0:5
    scripts/record-commands.py B02 --spec evidence/B02/commands.spec.json --range 5: --append

Usage:
    scripts/record-commands.py B00 --spec evidence/B00/commands.spec.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_TAIL = 4000


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_one(entry: dict, batch_dir: Path) -> dict:
    command = entry["command"]
    started = time.monotonic()
    proc = subprocess.run(command, shell=True, cwd=ROOT, capture_output=True, text=True)
    duration_ms = int((time.monotonic() - started) * 1000)
    combined = proc.stdout + proc.stderr
    record = {
        "timestamp": now(),
        "command": command,
        "exit_code": proc.returncode,
        "duration_ms": duration_ms,
        "purpose": entry.get("purpose", ""),
        "expected_exit_code": entry.get("expect", 0),
        "output_sha256": hashlib.sha256(combined.encode("utf-8")).hexdigest(),
        "output_tail": combined[-MAX_TAIL:],
    }
    artefact = entry.get("save_to")
    if artefact:
        target = batch_dir / artefact
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(combined, encoding="utf-8")
        record["saved_to"] = artefact
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("batch")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--range", dest="slice_spec", default=":",
                        help="python-style slice over the command list, e.g. '0:5' or '5:'")
    parser.add_argument("--append", action="store_true",
                        help="append to an existing commands.ndjson instead of replacing it")
    args = parser.parse_args()

    batch_dir = ROOT / "evidence" / args.batch
    batch_dir.mkdir(parents=True, exist_ok=True)
    spec = json.loads((ROOT / args.spec).read_text(encoding="utf-8"))

    start_text, _, stop_text = args.slice_spec.partition(":")
    start = int(start_text) if start_text else None
    stop = int(stop_text) if stop_text else None
    selected = spec["commands"][slice(start, stop)]

    records = [run_one(entry, batch_dir) for entry in selected]
    ndjson = batch_dir / "commands.ndjson"
    with ndjson.open("a" if args.append else "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    mismatched = [r for r in records if r["exit_code"] != r["expected_exit_code"]]
    print(json.dumps({
        "batch": args.batch,
        "commands": len(records),
        "unexpected_exit_codes": [
            {"command": r["command"], "exit_code": r["exit_code"],
             "expected": r["expected_exit_code"]} for r in mismatched],
    }, ensure_ascii=False, indent=2))
    return 0 if not mismatched else 1


if __name__ == "__main__":
    raise SystemExit(main())
