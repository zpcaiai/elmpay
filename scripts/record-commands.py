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
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.evidence import (command_log_problems, command_spec_sha256,  # noqa: E402
                                   load_command_records)

MAX_TAIL = 4000


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def _contained(base: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError(f"unsafe output path: {relative!r}")
    target = (base / relative).resolve(strict=False)
    try:
        target.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"output path escapes {base}: {relative}") from exc
    return target


def _option_values(tokens: list[str], option: str) -> list[str | None]:
    values: list[str | None] = []
    for index, token in enumerate(tokens):
        if token == option:
            values.append(tokens[index + 1] if index + 1 < len(tokens)
                          and not tokens[index + 1].startswith("--") else None)
        elif token.startswith(option + "="):
            values.append(token.split("=", 1)[1])
    return values


def _declared_outputs(entry: dict) -> list[str]:
    """Outputs whose freshness must be proven, including test summaries."""
    outputs = entry.get("outputs", [])
    if outputs is None:
        outputs = []
    if not isinstance(outputs, list) or not all(isinstance(item, str) for item in outputs):
        raise ValueError("command outputs must be an array of repository-relative paths")
    command = entry.get("command")
    try:
        tokens = shlex.split(command)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"command cannot be parsed: {exc}") from exc
    if any(token == "scripts/test-summary.py" or
           token.endswith("/scripts/test-summary.py") for token in tokens):
        values = _option_values(tokens, "--out")
        if len(values) != 1 or values[0] is None:
            raise ValueError("test-summary command must have exactly one --out path")
        outputs = [*outputs, values[0]]
    return list(dict.fromkeys(outputs))


def _fingerprint(path: Path) -> tuple[int, int, int, int] | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size


def run_one(entry: dict, batch_dir: Path, *, spec_index: int = 0,
            spec_sha256: str = "") -> dict:
    command = entry["command"]
    output_paths = [_contained(ROOT, relative) for relative in _declared_outputs(entry)]
    artefact = entry.get("save_to")
    save_target = _contained(batch_dir, artefact) if artefact else None
    before = {path: _fingerprint(path) for path in output_paths}
    started = time.monotonic()
    proc = subprocess.run(command, shell=True, cwd=ROOT, capture_output=True, text=True)
    duration_ms = int((time.monotonic() - started) * 1000)
    combined = proc.stdout + proc.stderr
    record = {
        "timestamp": now(),
        "spec_index": spec_index,
        "spec_sha256": spec_sha256,
        "command": command,
        "exit_code": proc.returncode,
        "duration_ms": duration_ms,
        "purpose": entry.get("purpose", ""),
        "expected_exit_code": entry.get("expect", 0),
        "output_sha256": hashlib.sha256(combined.encode("utf-8")).hexdigest(),
        "output_bytes": len(combined.encode("utf-8")),
        "output_tail": combined[-MAX_TAIL:],
    }
    if save_target is not None:
        _atomic_write(save_target, combined.encode("utf-8"))
        record["saved_to"] = artefact
        record["saved_output_sha256"] = hashlib.sha256(save_target.read_bytes()).hexdigest()
    produced = []
    for relative, path in zip(_declared_outputs(entry), output_paths):
        after = _fingerprint(path)
        item = {"path": relative, "fresh": after is not None and after != before[path]}
        if path.is_file():
            payload = path.read_bytes()
            item.update({"sha256": hashlib.sha256(payload).hexdigest(),
                         "bytes": len(payload)})
        produced.append(item)
    if produced:
        record["produced_outputs"] = produced
    return record


def _parse_slice(raw: str, length: int) -> list[int]:
    if raw.count(":") != 1:
        raise ValueError("--range must be START:STOP")
    start_text, stop_text = raw.split(":", 1)
    if (start_text and not start_text.isdigit()) or (stop_text and not stop_text.isdigit()):
        raise ValueError("--range bounds must be non-negative integers")
    start = int(start_text) if start_text else 0
    stop = int(stop_text) if stop_text else length
    if start > stop:
        raise ValueError("--range START may not exceed STOP")
    return list(range(length))[slice(start, stop)]


def _records_bytes(records: list[dict]) -> bytes:
    return ("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)
            .encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("batch")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--range", dest="slice_spec", default=":",
                        help="python-style slice over the command list, e.g. '0:5' or '5:'")
    parser.add_argument("--append", action="store_true",
                        help="append to an existing commands.ndjson instead of replacing it")
    args = parser.parse_args(argv)

    if re.fullmatch(r"B[0-9]{2,3}", args.batch) is None:
        print(json.dumps({"batch": args.batch, "error": "batch must be B followed by 2-3 digits"},
                         ensure_ascii=False, indent=2))
        return 2
    batch_dir = ROOT / "evidence" / args.batch
    batch_dir.mkdir(parents=True, exist_ok=True)
    try:
        spec_path = _contained(ROOT, args.spec)
    except ValueError as exc:
        print(json.dumps({"batch": args.batch, "error": str(exc)}, ensure_ascii=False,
                         indent=2))
        return 2
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        commands = spec["commands"]
        if not isinstance(commands, list) or not commands:
            raise ValueError("commands must be a non-empty array")
        if spec.get("batch") not in (None, args.batch):
            raise ValueError(f"spec batch {spec.get('batch')!r} does not match {args.batch}")
        for position, entry in enumerate(commands):
            if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
                raise ValueError(f"command {position} is malformed")
            if not isinstance(entry.get("expect", 0), int):
                raise ValueError(f"command {position} expect must be an integer")
        selected_indices = _parse_slice(args.slice_spec, len(commands))
        if not selected_indices:
            raise ValueError("--range selects no commands")
        if selected_indices != list(range(selected_indices[0], selected_indices[-1] + 1)):
            raise ValueError("--range must select one contiguous command slice")
        digest = command_spec_sha256(spec_path)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"batch": args.batch, "error": str(exc)}, ensure_ascii=False,
                         indent=2))
        return 2

    ndjson = batch_dir / "commands.ndjson"
    existing: list[dict] = []
    if args.append:
        try:
            existing = load_command_records(ndjson) if ndjson.is_file() else []
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"batch": args.batch,
                              "error": f"existing command log is unreadable: {exc}"},
                             ensure_ascii=False, indent=2))
            return 2
        prefix_problems = command_log_problems(ROOT, batch_dir, commands, existing, digest,
                                               require_complete=False)
        if prefix_problems:
            print(json.dumps({"batch": args.batch, "error": "existing command log is invalid",
                              "problems": prefix_problems}, ensure_ascii=False, indent=2))
            return 2
        if selected_indices[0] != len(existing):
            print(json.dumps({"batch": args.batch,
                              "error": "append range must start at the next spec command",
                              "next_index": len(existing),
                              "selected_start": selected_indices[0]},
                             ensure_ascii=False, indent=2))
            return 2
    elif selected_indices[0] != 0:
        print(json.dumps({"batch": args.batch,
                          "error": "a replacement command log must start at spec command 0"},
                         ensure_ascii=False, indent=2))
        return 2

    records: list[dict] = []
    output_errors: list[dict] = []
    for index in selected_indices:
        try:
            record = run_one(commands[index], batch_dir, spec_index=index,
                             spec_sha256=digest)
        except (OSError, ValueError) as exc:
            output_errors.append({"spec_index": index, "error": str(exc)})
            break
        records.append(record)
        stale = [item["path"] for item in record.get("produced_outputs", [])
                 if not item.get("fresh") or "sha256" not in item]
        if stale:
            output_errors.append({"spec_index": index,
                                  "error": "declared outputs were not freshly produced",
                                  "outputs": stale})
            break
        if record["exit_code"] != record["expected_exit_code"]:
            break

    mismatched = [record for record in records
                  if record["exit_code"] != record["expected_exit_code"]]
    if not mismatched and not output_errors and len(records) == len(selected_indices):
        combined = existing + records
        try:
            spec_unchanged = command_spec_sha256(spec_path) == digest
        except OSError:
            spec_unchanged = False
        if not spec_unchanged:
            output_errors.append({"error": "command spec changed while the slice was running"})
        transcript_problems = command_log_problems(
            ROOT, batch_dir, commands, combined, digest, require_complete=False)
        if transcript_problems:
            output_errors.append({"error": "new command transcript is invalid",
                                  "problems": transcript_problems})
        elif not output_errors:
            _atomic_write(ndjson, _records_bytes(combined))

    print(json.dumps({
        "batch": args.batch,
        "commands": len(records),
        "unexpected_exit_codes": [
            {"command": r["command"], "exit_code": r["exit_code"],
             "expected": r["expected_exit_code"]} for r in mismatched],
        "output_errors": output_errors,
    }, ensure_ascii=False, indent=2))
    return 0 if not mismatched and not output_errors \
        and len(records) == len(selected_indices) else 1


if __name__ == "__main__":
    raise SystemExit(main())
