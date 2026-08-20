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
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.evidence import (command_log_problems, command_spec_sha256,  # noqa: E402
                                   load_command_records)

ORCHESTRATOR = ".payment-platform/skill-package/scripts/orchestrate.py"
HEX64 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{7,64}$")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _restore_completion(path: Path, previous: bytes | None) -> None:
    if previous is not None:
        _atomic_write(path, previous)
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _final_validate(batch: str, completion: Path, previous: bytes | None) -> int:
    """Validate the new marker, rolling it back on every rejection."""
    step = run([sys.executable, ORCHESTRATOR, "validate", batch, "--repo", "."])
    print(step.stdout + step.stderr)
    if step.returncode == 0:
        return 0
    try:
        _restore_completion(completion, previous)
    except OSError as exc:
        print(f"[{batch}] final validation failed and completion rollback failed: {exc}")
        return 2
    print(f"[{batch}] final validation failed; previous completion state restored")
    return 2


def _option_values(tokens: list[str], option: str) -> list[str | None]:
    values: list[str | None] = []
    for index, token in enumerate(tokens):
        if token == option:
            values.append(tokens[index + 1] if index + 1 < len(tokens)
                          and not tokens[index + 1].startswith("--") else None)
        elif token.startswith(option + "="):
            values.append(token.split("=", 1)[1])
    return values


def _slice_indices(raw: str, length: int) -> list[int]:
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


def _summary_problems(base: Path, batch: str, commands: list[dict],
                      records: list[dict]) -> tuple[list[str], dict | None]:
    """Bind the consumed summary to the current run's exact producer record."""
    relative = f"evidence/{batch}/test-results/summary.json"
    producers: list[tuple[int, list[str]]] = []
    shard_labels: list[tuple[int, int]] = []
    for index, entry in enumerate(commands):
        try:
            tokens = shlex.split(entry["command"])
        except (KeyError, TypeError, ValueError):
            continue
        if not any(token == "scripts/test-summary.py" or
                   token.endswith("/scripts/test-summary.py") for token in tokens):
            continue
        outputs = _option_values(tokens, "--out")
        if outputs == [relative]:
            producers.append((index, tokens))
        labels = _option_values(tokens, "--shard")
        if labels:
            if len(labels) != 1 or labels[0] is None \
                    or re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", labels[0]) is None:
                return (["test-summary has malformed shard metadata"], None)
            shard, total = (int(value) for value in labels[0].split("/"))
            if shard > total:
                return (["test-summary shard index is outside its partition"], None)
            shard_labels.append((shard, total))
    if len(producers) != 1:
        return (["current spec must have exactly one producer for test-results/summary.json"],
                None)
    producer_index, producer_tokens = producers[0]
    if shard_labels:
        totals = {total for _, total in shard_labels}
        if len(totals) != 1:
            return (["test-summary shards mix partition sizes"], None)
        expected_shards = next(iter(totals))
        if sorted(shard_labels) != [(index, expected_shards)
                                    for index in range(1, expected_shards + 1)]:
            return (["test-summary shard set is not exactly 1..N"], None)
        if "--merge" not in producer_tokens:
            return (["sharded test-summary final output was not produced by its merge"], None)
    else:
        expected_shards = 1
        if "--merge" in producer_tokens:
            return (["unsharded test-summary may not use a merge"], None)

    try:
        record = records[producer_index]
    except IndexError:
        return (["test-summary producer has no command record"], None)
    proofs = [item for item in record.get("produced_outputs", [])
              if isinstance(item, dict) and item.get("path") == relative]
    summary_path = base / "test-results" / "summary.json"
    if len(proofs) != 1 or not proofs[0].get("fresh") or not summary_path.is_file():
        return (["test-results/summary.json was not freshly produced by the recorded command"],
                None)
    if proofs[0].get("sha256") != sha256(summary_path) \
            or proofs[0].get("bytes") != summary_path.stat().st_size:
        return (["test-results/summary.json no longer matches its command output proof"], None)
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ([f"test-results/summary.json is unreadable: {exc}"], None)
    if not isinstance(summary, dict):
        return (["test-results/summary.json must be an object"], None)
    problems: list[str] = []
    if summary.get("shards") != expected_shards:
        problems.append(f"test summary must declare shards={expected_shards}")
    for key in ("run", "passed", "failed", "skipped", "skipped_critical"):
        if not isinstance(summary.get(key), int) or isinstance(summary.get(key), bool) \
                or summary[key] < 0:
            problems.append(f"test summary {key} must be a non-negative integer")
    if not problems:
        if summary["failed"] or summary["skipped_critical"]:
            problems.append("test summary is not clean")
        if summary["run"] != summary["passed"]:
            problems.append("test summary run and passed counts differ")
    return problems, summary


def _git_head() -> str:
    step = run(["git", "rev-parse", "--verify", "HEAD"])
    head = step.stdout.strip().lower()
    if step.returncode != 0 or re.fullmatch(r"[a-f0-9]{7,64}", head) is None:
        raise ValueError("cannot resolve current Git HEAD")
    return head


def _review_problems(path: Path, batch: str, spec: Path, artifacts: Path) -> list[str]:
    problems: list[str] = []
    base = (ROOT / "evidence" / batch).resolve()
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError):
        return ["review attestation must be an existing file inside the batch evidence directory"]
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    tracked = run(["git", "ls-files", "--error-unmatch", "--", relative])
    if tracked.returncode != 0:
        problems.append("review attestation must be tracked by Git")
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return problems + [f"review attestation is unreadable: {exc}"]
    if not isinstance(data, dict):
        return problems + ["review attestation must be an object"]
    expected_top = {"schema_version", "batch_id", "decision", "reviewer", "executor",
                    "reviewed_at", "scope", "notes", "bindings"}
    if set(data) != expected_top:
        problems.append(f"review attestation keys must be exactly {sorted(expected_top)}")
    config_path = ROOT / "governance" / "project-config.json"
    manifest = ROOT / ".payment-platform" / "skill-package" / "manifest.json"
    try:
        identities = json.loads(config_path.read_text(encoding="utf-8"))["evidence"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        return problems + [f"cannot load configured evidence identities: {exc}"]
    if data.get("schema_version") != "1.0.0":
        problems.append("review schema_version must be 1.0.0")
    if data.get("batch_id") != batch or data.get("decision") != "approved":
        problems.append("review must approve the current batch")
    if data.get("reviewer") != identities.get("reviewer") \
            or data.get("executor") != identities.get("executor"):
        problems.append("review principals do not match project configuration")
    if data.get("reviewer") == data.get("executor"):
        problems.append("reviewer and executor must differ")
    if not isinstance(data.get("scope"), str) or not data["scope"].strip():
        problems.append("review scope must be non-empty")
    if not isinstance(data.get("notes"), str) or not data["notes"].strip():
        problems.append("review notes must be a non-empty string")
    try:
        reviewed_at = datetime.fromisoformat(
            data.get("reviewed_at", "").replace("Z", "+00:00"))
        if reviewed_at.tzinfo is None or reviewed_at.utcoffset() is None:
            raise ValueError("timestamp has no UTC offset")
    except (AttributeError, ValueError):
        problems.append("reviewed_at must be an ISO-8601 timestamp with timezone")

    bindings = data.get("bindings")
    expected_binding_keys = {"git_head", "manifest_sha256", "commands_spec_sha256",
                             "artifacts_json_sha256", "traceability_sha256", "artifacts"}
    if not isinstance(bindings, dict):
        return problems + ["review bindings must be an object"]
    if set(bindings) != expected_binding_keys:
        problems.append(f"review binding keys must be exactly {sorted(expected_binding_keys)}")
    try:
        declared = json.loads(artifacts.read_text(encoding="utf-8"))
        if not isinstance(declared, list) or not declared \
                or not all(isinstance(item, str) and item for item in declared) \
                or len(declared) != len(set(declared)):
            raise ValueError("artifacts.json must be a non-empty array of unique paths")
        artifact_hashes = {}
        for relative in declared:
            target = (ROOT / relative).resolve(strict=True)
            target.relative_to(ROOT.resolve())
            if not target.is_file():
                raise ValueError(f"artifact is not a file: {relative}")
            artifact_hashes[relative] = sha256(target)
        expected = {
            "git_head": _git_head(),
            "manifest_sha256": sha256(manifest),
            "commands_spec_sha256": command_spec_sha256(spec),
            "artifacts_json_sha256": sha256(artifacts),
            "traceability_sha256": sha256(base / "traceability.json"),
            "artifacts": artifact_hashes,
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return problems + [f"cannot compute review bindings: {exc}"]
    commit = bindings.get("git_head")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None \
            or commit != expected["git_head"]:
        problems.append("review binding git_head does not match current repository state")
    for key in ("manifest_sha256", "commands_spec_sha256", "artifacts_json_sha256",
                "traceability_sha256"):
        value = bindings.get(key)
        if not isinstance(value, str) or HEX64.fullmatch(value) is None \
                or value != expected[key]:
            problems.append(f"review binding {key} does not match current repository state")
    if bindings.get("artifacts") != expected["artifacts"]:
        problems.append("review artifact hash set does not exactly match artifacts.json")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("batch")
    parser.add_argument("--accepted-findings", type=int, default=0)
    parser.add_argument("--range", dest="slice_spec", default=":",
                        help="record only this slice of the command spec")
    parser.add_argument("--append", action="store_true",
                        help="append to the existing command log instead of replacing it")
    parser.add_argument("--record-only", action="store_true",
                        help="record commands and stop, without writing the completion file")
    parser.add_argument("--review-attestation",
                        help="tracked independent approval bound to current HEAD and inputs")
    args = parser.parse_args(argv)
    batch = args.batch
    if re.fullmatch(r"B[0-9]{2,3}", batch) is None:
        print("batch must be B followed by 2-3 digits")
        return 3
    base = ROOT / "evidence" / batch

    spec = base / "commands.spec.json"
    artifacts = base / "artifacts.json"
    for path in (spec, artifacts):
        if not path.is_file():
            print(f"missing required input: {path.relative_to(ROOT)}")
            return 3

    try:
        spec_payload = json.loads(spec.read_text(encoding="utf-8"))
        commands = spec_payload["commands"]
        if not isinstance(commands, list) or not commands:
            raise ValueError("commands must be a non-empty array")
        if spec_payload.get("batch") not in (None, batch):
            raise ValueError(f"spec batch {spec_payload.get('batch')!r} does not match {batch}")
        selected_indices = _slice_indices(args.slice_spec, len(commands))
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"[{batch}] invalid command spec or range: {exc}")
        return 3

    if not args.record_only and not args.review_attestation:
        print(f"[{batch}] --review-attestation is required for completion")
        return 3

    # A resume driver may finish with N:N after it has recorded the final
    # command.  That empty range is not execution evidence: it is accepted only
    # in append/finalize mode, and the full current transcript is still checked
    # below for exact ordered equality.  Every other empty range is refused.
    if selected_indices:
        record_cmd = [sys.executable, "scripts/record-commands.py", batch,
                      "--spec", str(spec.relative_to(ROOT)), "--range", args.slice_spec]
        if args.append:
            record_cmd.append("--append")
        step = run(record_cmd)
        print(step.stdout + step.stderr)
        if step.returncode != 0:
            print(f"[{batch}] recorded commands did not all match their expected exit codes")
            return 2
    elif args.record_only or not args.append or args.slice_spec != f"{len(commands)}:{len(commands)}":
        print(f"[{batch}] empty --range is only valid for append finalization of a complete log")
        return 2
    else:
        print(f"[{batch}] empty range recorded nothing; validating the complete existing log")

    if args.record_only:
        print(f"[{batch}] recorded slice {args.slice_spec}; completion not written")
        return 0

    ndjson = base / "commands.ndjson"
    try:
        records = load_command_records(ndjson)
        transcript_problems = command_log_problems(
            ROOT, base, commands, records, command_spec_sha256(spec), require_complete=True)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        transcript_problems = [f"command transcript is unreadable: {exc}"]
        records = []
    if transcript_problems:
        print(f"[{batch}] command transcript does not prove the current spec:")
        for problem in transcript_problems:
            print(f"- {problem}")
        return 2

    summary_problems, summary = _summary_problems(base, batch, commands, records)
    if summary_problems or summary is None:
        print(f"[{batch}] test summary is not current and complete:")
        for problem in summary_problems:
            print(f"- {problem}")
        return 2

    review_path = ROOT / args.review_attestation
    review_problems = _review_problems(review_path, batch, spec, artifacts)
    if review_problems:
        print(f"[{batch}] independent review attestation is invalid:")
        for problem in review_problems:
            print(f"- {problem}")
        return 2

    started, completed = records[0]["timestamp"], records[-1]["timestamp"]

    completion_path = ROOT / "evidence" / "completion" / f"{batch}.json"
    previous_completion = completion_path.read_bytes() if completion_path.is_file() else None
    step = run([sys.executable, "scripts/make-completion.py", batch,
                "--artifacts", str(artifacts.relative_to(ROOT)),
                "--review-attestation", str(review_path.relative_to(ROOT)),
                "--started-at", started, "--completed-at", completed,
                "--tests-passed", str(summary["passed"]),
                "--accepted-findings", str(args.accepted_findings)])
    print(step.stdout + step.stderr)
    if step.returncode != 0:
        return 2

    return _final_validate(batch, completion_path, previous_completion)


if __name__ == "__main__":
    raise SystemExit(main())
