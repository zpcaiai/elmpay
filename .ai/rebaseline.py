#!/usr/bin/env python3
"""Safe, resumable evidence re-baselining for the payment-platform programme.

This CLI deliberately separates four operations:

* ``status`` inspects a range and any saved command-level progress;
* ``migrate-shards`` performs the one-time, idempotent command-spec migration;
* ``resume`` records commands without changing command specifications;
* ``reset`` discards local resume state.

Resume state is local, locked, atomically written, and bound to the repository,
Git HEAD, manifest, requested range, and every command specification.  A state
file is therefore never silently reused after source or evidence inputs move.

Completion is a separate trust boundary.  Recording commands does not confer
independent review.  ``resume`` stops at ``review-blocked`` unless an explicit
``evidence/<batch>/review.json`` approves the exact current HEAD, manifest,
command spec, and artifact hashes.  Traceability is finalized only after that
review and all command/output proofs pass.  The CLI never creates the
attestation and has no flag that bypasses it.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
from datetime import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_REL = Path(".payment-platform/skill-package/manifest.json")
STATE_REL = Path(".ai/.state/rebaseline.json")
LOCK_REL = Path(".ai/.state/rebaseline.lock")
STATE_SCHEMA = 2
DEFAULT_LAUNCH_WINDOW_SECONDS = 36.0
DEFAULT_SHARDS = 4
BATCH_ID = re.compile(r"^[Bb](\d+)$")
SHARD_VALUE = re.compile(r"^([1-9][0-9]*)/([1-9][0-9]*)$")
SHARDED_NAME = re.compile(r"-(\d+)of(\d+)(?=(?:\.[^/]*)?$)")
HEX64 = re.compile(r"^[a-f0-9]{64}$")


class RebaselineError(RuntimeError):
    """An operational refusal that should exit nonzero without a traceback."""


class StaleState(RebaselineError):
    """Saved progress does not describe the live repository any more."""


class LockBusy(RebaselineError):
    """Another rebaseline process currently owns the repository lock."""


class ReviewBlocked(RebaselineError):
    """Commands are recorded, but independent human approval is not current."""

    def __init__(self, batch: str, reason: str, expected: dict[str, Any]) -> None:
        super().__init__(reason)
        self.batch = batch
        self.reason = reason
        self.expected = expected


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RebaselineError(f"missing required file: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RebaselineError(f"cannot read JSON {path}: {exc}") from exc


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Replace ``path`` atomically and durably using a sibling temporary file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, _json_bytes(value))


@contextlib.contextmanager
def state_lock(root: Path) -> Iterator[None]:
    """Take the repository's exclusive lock without waiting."""
    lock_path = root.resolve() / LOCK_REL
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy(f"rebaseline lock is already held: {lock_path}") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def manifest_path(root: Path) -> Path:
    return root.resolve() / MANIFEST_REL


def manifest_order(root: Path) -> list[str]:
    payload = _load_json(manifest_path(root))
    batches = payload.get("batches") if isinstance(payload, dict) else None
    if not isinstance(batches, list) or not batches:
        raise RebaselineError("manifest.batches must be a non-empty array")
    order: list[str] = []
    numbers: dict[int, str] = {}
    for item in batches:
        raw = item.get("id") if isinstance(item, dict) else None
        match = BATCH_ID.fullmatch(raw or "")
        if match is None:
            raise RebaselineError(f"manifest contains invalid batch id: {raw!r}")
        number = int(match.group(1))
        if number in numbers:
            raise RebaselineError(
                f"manifest batch ids {numbers[number]} and {raw} normalize to the same number"
            )
        numbers[number] = raw
        order.append(raw)
    return order


def normalize_batch_id(raw: str, order: list[str]) -> str:
    """Resolve padded IDs such as B000 and B0127 to the manifest spelling."""
    match = BATCH_ID.fullmatch(raw or "")
    if match is None:
        raise RebaselineError(f"invalid batch id {raw!r}; expected B followed by digits")
    wanted = int(match.group(1))
    matches = [batch for batch in order if int(batch[1:]) == wanted]
    if len(matches) != 1:
        raise RebaselineError(f"batch {raw!r} is not present exactly once in the manifest")
    return matches[0]


def spec_path(root: Path, batch: str) -> Path:
    return root.resolve() / "evidence" / batch / "commands.spec.json"


def trace_path(root: Path, batch: str) -> Path:
    return root.resolve() / "evidence" / batch / "traceability.json"


def artifacts_path(root: Path, batch: str) -> Path:
    return root.resolve() / "evidence" / batch / "artifacts.json"


def resolve_range(
    root: Path, batch_from: str | None = None, batch_to: str | None = None
) -> list[str]:
    order = manifest_order(root)
    available = [batch for batch in order if spec_path(root, batch).is_file()]
    if not available:
        raise RebaselineError("no command specifications exist in this repository")
    first = normalize_batch_id(batch_from, order) if batch_from else available[0]
    last = normalize_batch_id(batch_to, order) if batch_to else available[-1]
    start, stop = order.index(first), order.index(last)
    if start > stop:
        raise RebaselineError(f"invalid range: --from {first} comes after --to {last}")
    batches = order[start : stop + 1]
    missing = [batch for batch in batches if not spec_path(root, batch).is_file()]
    if missing:
        raise RebaselineError(
            "range contains batches without command specifications: " + ", ".join(missing)
        )
    return batches


def git_head(root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root.resolve()), "rev-parse", "--verify", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    head = proc.stdout.strip()
    if proc.returncode != 0 or re.fullmatch(r"[0-9a-fA-F]{7,64}", head) is None:
        detail = (proc.stderr or proc.stdout).strip()
        raise RebaselineError(f"cannot resolve Git HEAD for {root.resolve()}: {detail}")
    return head.lower()


def current_binding(
    root: Path, batches: list[str], *, head: str | None = None
) -> dict[str, Any]:
    real_root = root.resolve()
    return {
        "repo_realpath": str(real_root),
        "git_head": (head or git_head(real_root)).lower(),
        "manifest_sha256": sha256_file(manifest_path(real_root)),
        "range": {"from": batches[0], "to": batches[-1]},
        "command_spec_sha256": {
            batch: sha256_file(spec_path(real_root, batch)) for batch in batches
        },
    }


def new_state(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA,
        "binding": copy.deepcopy(binding),
        "progress": {
            "batch_index": 0,
            "command_index": 0,
            "command_started": False,
        },
    }


def state_path(root: Path) -> Path:
    return root.resolve() / STATE_REL


def _binding_differences(saved: Any, live: dict[str, Any]) -> list[str]:
    if not isinstance(saved, dict):
        return ["binding is not an object"]
    differences = []
    for key in (
        "repo_realpath",
        "git_head",
        "manifest_sha256",
        "range",
        "command_spec_sha256",
    ):
        if saved.get(key) != live.get(key):
            differences.append(key)
    extra = sorted(set(saved) - set(live))
    if extra:
        differences.append("unexpected fields: " + ", ".join(extra))
    return differences


def validate_state(
    state: Any, binding: dict[str, Any], batches: list[str], root: Path
) -> dict[str, Any]:
    if not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA:
        raise StaleState("resume state has an unknown schema; reset it explicitly")
    differences = _binding_differences(state.get("binding"), binding)
    if differences:
        raise StaleState(
            "resume state is stale (" + ", ".join(differences) + "); run reset explicitly"
        )
    progress = state.get("progress")
    if not isinstance(progress, dict):
        raise StaleState("resume state progress is malformed; reset it explicitly")
    batch_index, command_index = progress.get("batch_index"), progress.get("command_index")
    command_started = progress.get("command_started")
    if not isinstance(batch_index, int) or not isinstance(command_index, int):
        raise StaleState("resume indices must be integers")
    if not isinstance(command_started, bool):
        raise StaleState("resume command_started marker must be a boolean")
    if not 0 <= batch_index <= len(batches):
        raise StaleState("resume batch index is outside the bound range")
    if batch_index == len(batches):
        if command_index != 0 or command_started:
            raise StaleState(
                "completed resume state must have command_index=0 and command_started=false"
            )
        return state
    commands = read_commands(root, batches[batch_index])
    if not 0 <= command_index <= len(commands):
        raise StaleState("resume command index is outside the bound command spec")
    return state


def load_state(
    root: Path, binding: dict[str, Any], batches: list[str]
) -> dict[str, Any] | None:
    path = state_path(root)
    if not path.is_file():
        return None
    return validate_state(_load_json(path), binding, batches, root)


def save_state(root: Path, state: dict[str, Any]) -> None:
    atomic_write_json(state_path(root), state)


def read_commands(root: Path, batch: str) -> list[dict[str, Any]]:
    payload = _load_json(spec_path(root, batch))
    commands = payload.get("commands") if isinstance(payload, dict) else None
    if not isinstance(commands, list) or not commands:
        raise RebaselineError(f"{batch} commands.spec.json must contain a non-empty commands array")
    for index, entry in enumerate(commands):
        if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
            raise RebaselineError(f"{batch} command {index} is malformed")
    return commands


def _tokens(batch: str, entry: dict[str, Any]) -> list[str]:
    try:
        tokens = shlex.split(entry["command"])
    except ValueError as exc:
        raise RebaselineError(f"{batch} has an unparseable command: {exc}") from exc
    if not tokens:
        raise RebaselineError(f"{batch} has an empty command")
    return tokens


def _script_index(tokens: list[str], script: str) -> int | None:
    suffix = "/" + script.lstrip("./")
    for index, token in enumerate(tokens):
        normalized = "/" + token.lstrip("./")
        if normalized.endswith(suffix):
            return index
    return None


def _option_value(
    batch: str, tokens: list[str], option: str, *, required: bool = False
) -> str | None:
    positions = [index for index, token in enumerate(tokens) if token == option]
    if len(positions) > 1:
        raise RebaselineError(f"{batch} command repeats {option}")
    if not positions:
        if required:
            raise RebaselineError(f"{batch} command is missing {option}")
        return None
    position = positions[0]
    if position + 1 >= len(tokens) or tokens[position + 1].startswith("--"):
        raise RebaselineError(f"{batch} command has no value for {option}")
    return tokens[position + 1]


def _replace_option(batch: str, tokens: list[str], option: str, value: str) -> list[str]:
    updated = list(tokens)
    old = _option_value(batch, updated, option, required=True)
    position = updated.index(option)
    if old is None:  # pragma: no cover - required=True makes this unreachable
        raise RebaselineError(f"{batch} command is missing {option}")
    updated[position + 1] = value
    return updated


def _parse_shard_value(batch: str, raw: str | None) -> tuple[int, int] | None:
    if raw is None:
        return None
    match = SHARD_VALUE.fullmatch(raw)
    if match is None:
        raise RebaselineError(f"{batch} has malformed shard label {raw!r}")
    index, count = int(match.group(1)), int(match.group(2))
    if index > count:
        raise RebaselineError(f"{batch} shard {raw} is outside 1..{count}")
    return index, count


def _merge_inputs(batch: str, tokens: list[str]) -> list[str]:
    if "--merge" not in tokens:
        return []
    position = tokens.index("--merge") + 1
    inputs = []
    while position < len(tokens) and not tokens[position].startswith("--"):
        inputs.append(tokens[position])
        position += 1
    if not inputs:
        raise RebaselineError(f"{batch} test-summary merge has no inputs")
    return inputs


def _sharded_path(path: str, index: int, count: int) -> str:
    pure = PurePosixPath(path)
    suffix = pure.suffix
    stem = pure.name[: -len(suffix)] if suffix else pure.name
    name = f"{stem}-{index}of{count}{suffix}"
    return (pure.parent / name).as_posix()


def _negative_entries(
    batch: str, commands: list[dict[str, Any]]
) -> list[tuple[int, dict[str, Any], list[str], tuple[int, int] | None]]:
    found = []
    for position, entry in enumerate(commands):
        tokens = _tokens(batch, entry)
        if _script_index(tokens, "scripts/negative-controls.py") is None:
            continue
        label = _parse_shard_value(batch, _option_value(batch, tokens, "--shard"))
        found.append((position, entry, tokens, label))
    return found


def _test_summary_entries(
    batch: str, commands: list[dict[str, Any]]
) -> list[tuple[int, dict[str, Any], list[str], tuple[int, int] | str | None]]:
    found = []
    for position, entry in enumerate(commands):
        tokens = _tokens(batch, entry)
        if _script_index(tokens, "scripts/test-summary.py") is None:
            continue
        shard = _parse_shard_value(batch, _option_value(batch, tokens, "--shard"))
        kind: tuple[int, int] | str | None = "merge" if "--merge" in tokens else shard
        if "--merge" in tokens and shard is not None:
            raise RebaselineError(f"{batch} test-summary command mixes --merge and --shard")
        found.append((position, entry, tokens, kind))
    return found


def _validate_legacy_families(
    batch: str,
    negative: list[tuple[int, dict[str, Any], list[str], tuple[int, int] | None]],
    summaries: list[tuple[int, dict[str, Any], list[str], tuple[int, int] | str | None]],
) -> tuple[int, int]:
    if len(negative) != 1 or negative[0][3] is not None:
        raise RebaselineError(f"{batch} legacy spec must contain exactly one full negative-control command")
    if negative[0][1].get("save_to") != "security/negative-controls.log":
        raise RebaselineError(f"{batch} legacy negative-control output is not batch-local canonical")
    if len(summaries) != 1 or summaries[0][3] is not None:
        raise RebaselineError(f"{batch} legacy spec must contain exactly one full test-summary command")
    tokens = summaries[0][2]
    expected_out = f"evidence/{batch}/test-results/summary.json"
    expected_log = f"evidence/{batch}/test-results/unittest.log"
    if _option_value(batch, tokens, "--out", required=True) != expected_out:
        raise RebaselineError(f"{batch} legacy test-summary --out is not canonical")
    if _option_value(batch, tokens, "--log", required=True) != expected_log:
        raise RebaselineError(f"{batch} legacy test-summary --log is not canonical")
    if summaries[0][1].get("save_to") != "test-results/summary.log":
        raise RebaselineError(f"{batch} legacy test-summary save_to is not canonical")
    return negative[0][0], summaries[0][0]


def _validate_canonical_families(
    batch: str,
    commands: list[dict[str, Any]],
    shards: int,
) -> dict[str, Any]:
    negative = _negative_entries(batch, commands)
    summaries = _test_summary_entries(batch, commands)
    if len(negative) != shards:
        raise RebaselineError(
            f"{batch} negative-control family has {len(negative)} commands; expected {shards}"
        )
    negative_labels = [entry[3] for entry in negative]
    expected_labels = [(index, shards) for index in range(1, shards + 1)]
    if negative_labels != expected_labels:
        raise RebaselineError(
            f"{batch} negative-control shards must be exactly 1..{shards} in order; "
            f"got {negative_labels}"
        )
    negative_positions = [entry[0] for entry in negative]
    if negative_positions != list(range(negative_positions[0], negative_positions[0] + shards)):
        raise RebaselineError(f"{batch} negative-control shard commands are not contiguous")
    negative_logs = []
    for index, (_, entry, _, _) in enumerate(negative, 1):
        expected = f"security/negative-controls-{index}of{shards}.log"
        if entry.get("save_to") != expected:
            raise RebaselineError(f"{batch} shard {index}/{shards} must save to {expected}")
        negative_logs.append(f"evidence/{batch}/{expected}")

    if len(summaries) != shards + 1:
        raise RebaselineError(
            f"{batch} test-summary family must contain {shards} shards and one merge"
        )
    summary_kinds = [entry[3] for entry in summaries]
    if summary_kinds != expected_labels + ["merge"]:
        raise RebaselineError(
            f"{batch} test-summary shards and merge are incomplete or out of order: {summary_kinds}"
        )
    summary_positions = [entry[0] for entry in summaries]
    if summary_positions != list(range(summary_positions[0], summary_positions[0] + shards + 1)):
        raise RebaselineError(f"{batch} test-summary shard commands and merge are not contiguous")

    partial_summaries = []
    partial_logs = []
    summary_capture_logs = []
    for index, (_, entry, tokens, _) in enumerate(summaries[:-1], 1):
        expected_out = f"evidence/{batch}/test-results/summary-{index}of{shards}.json"
        expected_log = f"evidence/{batch}/test-results/unittest-{index}of{shards}.log"
        expected_capture = f"test-results/summary-{index}of{shards}.log"
        if _option_value(batch, tokens, "--out", required=True) != expected_out:
            raise RebaselineError(f"{batch} test shard {index}/{shards} has a noncanonical --out")
        if _option_value(batch, tokens, "--log", required=True) != expected_log:
            raise RebaselineError(f"{batch} test shard {index}/{shards} has a noncanonical --log")
        if entry.get("save_to") != expected_capture:
            raise RebaselineError(
                f"{batch} test shard {index}/{shards} must save to {expected_capture}"
            )
        partial_summaries.append(expected_out)
        partial_logs.append(expected_log)
        summary_capture_logs.append(f"evidence/{batch}/{expected_capture}")

    merge_entry, merge_tokens = summaries[-1][1], summaries[-1][2]
    if _merge_inputs(batch, merge_tokens) != partial_summaries:
        raise RebaselineError(f"{batch} test-summary merge inputs do not exactly match its shards")
    if _option_value(batch, merge_tokens, "--out", required=True) != (
        f"evidence/{batch}/test-results/summary.json"
    ):
        raise RebaselineError(f"{batch} test-summary merge has a noncanonical --out")
    if _option_value(batch, merge_tokens, "--log", required=True) != (
        f"evidence/{batch}/test-results/unittest.log"
    ):
        raise RebaselineError(f"{batch} test-summary merge has a noncanonical --log")
    if merge_entry.get("save_to") != "test-results/summary.log":
        raise RebaselineError(f"{batch} test-summary merge save_to is not canonical")
    return {
        "negative_logs": negative_logs,
        "negative_labels": expected_labels,
        "partial_summaries": partial_summaries,
        "partial_logs": partial_logs,
        "summary_capture_logs": summary_capture_logs,
        "merged_summary": f"evidence/{batch}/test-results/summary.json",
    }


def _migrate_legacy_spec(
    batch: str, payload: dict[str, Any], shards: int
) -> dict[str, Any]:
    commands = payload["commands"]
    negative = _negative_entries(batch, commands)
    summaries = _test_summary_entries(batch, commands)
    negative_position, summary_position = _validate_legacy_families(batch, negative, summaries)
    migrated: list[dict[str, Any]] = []
    for position, entry in enumerate(commands):
        if position == negative_position:
            tokens = _tokens(batch, entry)
            for index in range(1, shards + 1):
                item = copy.deepcopy(entry)
                item["command"] = shlex.join(tokens + ["--shard", f"{index}/{shards}"])
                item["save_to"] = f"security/negative-controls-{index}of{shards}.log"
                item["purpose"] = f"{entry.get('purpose', 'negative controls')} (shard {index}/{shards})"
                migrated.append(item)
            continue
        if position == summary_position:
            tokens = _tokens(batch, entry)
            output = _option_value(batch, tokens, "--out", required=True)
            verbose_log = _option_value(batch, tokens, "--log", required=True)
            if output is None or verbose_log is None:  # pragma: no cover - required above
                raise RebaselineError(f"{batch} test-summary paths are missing")
            partial_outputs = []
            script_index = _script_index(tokens, "scripts/test-summary.py")
            if script_index is None:  # pragma: no cover - classified above
                raise RebaselineError(f"{batch} test-summary script token is missing")
            for index in range(1, shards + 1):
                partial_out = _sharded_path(output, index, shards)
                partial_log = _sharded_path(verbose_log, index, shards)
                partial_outputs.append(partial_out)
                shard_tokens = _replace_option(batch, tokens, "--out", partial_out)
                shard_tokens = _replace_option(batch, shard_tokens, "--log", partial_log)
                shard_tokens += ["--shard", f"{index}/{shards}"]
                item = copy.deepcopy(entry)
                item["command"] = shlex.join(shard_tokens)
                item["save_to"] = f"test-results/summary-{index}of{shards}.log"
                item["purpose"] = f"{entry.get('purpose', 'test summary')} (shard {index}/{shards})"
                migrated.append(item)
            merge_tokens = tokens[: script_index + 1] + ["--merge", *partial_outputs, "--out", output]
            merge_tokens += ["--log", verbose_log]
            merge = copy.deepcopy(entry)
            merge["command"] = shlex.join(merge_tokens)
            merge["purpose"] = f"{entry.get('purpose', 'test summary')} (merge; missing shard fails)"
            migrated.append(merge)
            continue
        migrated.append(copy.deepcopy(entry))
    candidate = copy.deepcopy(payload)
    candidate["commands"] = migrated
    _validate_canonical_families(batch, candidate["commands"], shards)
    return candidate


def prepare_spec_migration(root: Path, batch: str, shards: int) -> dict[str, Any]:
    if shards < 2:
        raise RebaselineError("migrate-shards requires at least two shards")
    payload = _load_json(spec_path(root, batch))
    if not isinstance(payload, dict) or not isinstance(payload.get("commands"), list):
        raise RebaselineError(f"{batch} command specification is malformed")
    if payload.get("batch") != batch:
        raise RebaselineError(
            f"{batch} command specification identifies batch {payload.get('batch')!r}"
        )
    commands = payload["commands"]
    negative = _negative_entries(batch, commands)
    summaries = _test_summary_entries(batch, commands)
    negative_legacy = len(negative) == 1 and negative[0][3] is None
    summary_legacy = len(summaries) == 1 and summaries[0][3] is None
    if negative_legacy != summary_legacy:
        raise RebaselineError(
            f"{batch} is asymmetrically migrated; negative-control and test-summary families differ"
        )
    if negative_legacy:
        candidate = _migrate_legacy_spec(batch, payload, shards)
        changed = candidate != payload
    else:
        candidate = copy.deepcopy(payload)
        changed = False
    outputs = _validate_canonical_families(batch, candidate["commands"], shards)
    return {"payload": candidate, "changed": changed, "outputs": outputs}


def analyze_current_shards(root: Path, batch: str) -> dict[str, Any] | None:
    commands = read_commands(root, batch)
    negative = _negative_entries(batch, commands)
    summaries = _test_summary_entries(batch, commands)
    negative_legacy = len(negative) == 1 and negative[0][3] is None
    summary_legacy = len(summaries) == 1 and summaries[0][3] is None
    if negative_legacy and summary_legacy:
        _validate_legacy_families(batch, negative, summaries)
        return None
    if negative_legacy != summary_legacy:
        raise RebaselineError(
            f"{batch} is asymmetrically migrated; run migrate-shards only after diagnosing it"
        )
    if not negative or negative[0][3] is None:
        raise RebaselineError(f"{batch} has a malformed negative-control shard family")
    shard_count = negative[0][3][1]
    return _validate_canonical_families(batch, commands, shard_count)


def _nonempty_file(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def _negative_trace_entries(doc: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    evidence = doc.get("evidence")
    if not isinstance(evidence, list):
        raise RebaselineError("traceability.evidence must be an array")
    found = []
    for index, entry in enumerate(evidence):
        path = entry.get("path") if isinstance(entry, dict) else None
        if isinstance(path, str) and PurePosixPath(path).name.startswith("negative-controls"):
            found.append((index, entry))
    return found


def prepare_trace_plan(
    root: Path,
    batch: str,
    outputs: dict[str, Any],
    *,
    require_ready: bool,
) -> dict[str, Any]:
    path = trace_path(root, batch)
    raw = path.read_bytes() if path.is_file() else b""
    doc = _load_json(path)
    if not isinstance(doc, dict):
        raise RebaselineError(f"{batch} traceability must be an object")
    if doc.get("batch_id") != batch:
        raise RebaselineError(
            f"{batch} traceability identifies batch {doc.get('batch_id')!r}"
        )
    found = _negative_trace_entries(doc)
    legacy = f"evidence/{batch}/security/negative-controls.log"
    expected = list(outputs["negative_logs"])
    paths = [entry.get("path") for _, entry in found]
    ready = [_nonempty_file(root.resolve() / rel) for rel in expected]
    missing = [rel for rel, present in zip(expected, ready) if not present]

    if paths == expected:
        if missing:
            raise RebaselineError(
                f"{batch} traceability is finalized but shard logs are missing/empty: "
                + ", ".join(missing)
            )
        return {
            "phase": "finalized",
            "changed": False,
            "payload": doc,
            "target_bytes": raw,
            "recovery": None,
        }

    if not paths:
        completion = root.resolve() / "evidence" / "completion" / f"{batch}.json"
        if completion.is_file():
            raise RebaselineError(
                f"{batch} already has a completion claim but no negative-control trace entries"
            )
        if require_ready and missing:
            raise RebaselineError(
                f"{batch} cannot finalize new-batch traceability; shard logs are missing/empty: "
                + ", ".join(missing)
            )
        if missing:
            return {
                "phase": "staged-new-batch",
                "changed": False,
                "payload": doc,
                "target_bytes": raw,
                "recovery": None,
            }
        candidate = copy.deepcopy(doc)
        candidate["evidence"] += [{"path": rel, "kind": "security"} for rel in expected]
        return {
            "phase": "ready-to-finalize-new-batch",
            "changed": True,
            "payload": candidate,
            "target_bytes": _json_bytes(candidate),
            "recovery": None,
        }

    if paths != [legacy]:
        raise RebaselineError(
            f"{batch} negative-control trace entries are partial, mixed, or duplicated: {paths}"
        )
    if require_ready and missing:
        raise RebaselineError(
            f"{batch} cannot finalize traceability; shard logs are missing/empty: "
            + ", ".join(missing)
        )

    recovery = None
    legacy_target = root.resolve() / legacy
    if missing:
        if legacy_target.exists():
            if not _nonempty_file(legacy_target):
                raise RebaselineError(f"{batch} legacy negative-control log exists but is empty")
        else:
            source = (
                root.resolve()
                / "_to_delete"
                / "stale-negative-control-logs"
                / f"{batch}-negative-controls.log"
            )
            if not _nonempty_file(source):
                raise RebaselineError(
                    f"{batch} legacy trace bridge is missing and no nonempty recovery copy exists: {source}"
                )
            recovery = (source, legacy_target)
        return {
            "phase": "staged",
            "changed": False,
            "payload": doc,
            "target_bytes": raw,
            "recovery": recovery,
        }

    # All shard logs exist: the caller may write this only at the completion
    # boundary, after exact command-log checks and review attestation validation.
    replacement_index, template = found[0]
    evidence = copy.deepcopy(doc["evidence"])
    replacements = [{**copy.deepcopy(template), "path": rel} for rel in expected]
    evidence[replacement_index : replacement_index + 1] = replacements
    candidate = copy.deepcopy(doc)
    candidate["evidence"] = evidence
    return {
        "phase": "ready-to-finalize",
        "changed": True,
        "payload": candidate,
        "target_bytes": _json_bytes(candidate),
        "recovery": None,
    }


def prepare_batch_migration(root: Path, batch: str, shards: int) -> dict[str, Any]:
    spec = prepare_spec_migration(root, batch, shards)
    trace = prepare_trace_plan(root, batch, spec["outputs"], require_ready=False)
    # migrate-shards stages specifications and a legacy bridge only.  It never
    # finalizes traceability; that belongs to reviewed pre-completion.
    if trace["changed"] and trace["phase"] == "ready-to-finalize":
        legacy_target = root.resolve() / f"evidence/{batch}/security/negative-controls.log"
        recovery = None
        if legacy_target.exists():
            if not _nonempty_file(legacy_target):
                raise RebaselineError(f"{batch} legacy negative-control log exists but is empty")
        else:
            source = (
                root.resolve()
                / "_to_delete"
                / "stale-negative-control-logs"
                / f"{batch}-negative-controls.log"
            )
            if not _nonempty_file(source):
                raise RebaselineError(
                    f"{batch} cannot retain its legacy trace bridge; recovery copy is missing: {source}"
                )
            recovery = (source, legacy_target)
        trace = {
            **trace,
            "phase": "staged",
            "changed": False,
            "payload": _load_json(trace_path(root, batch)),
            "recovery": recovery,
        }
    elif trace["changed"] and trace["phase"] == "ready-to-finalize-new-batch":
        # A new batch deliberately has no legacy negative-control reference.
        # Migration only canonicalizes the spec; reviewed completion will add
        # shard references after the corresponding output proofs are checked.
        trace = {
            **trace,
            "phase": "staged-new-batch",
            "changed": False,
            "payload": _load_json(trace_path(root, batch)),
            "recovery": None,
        }
    return {"batch": batch, "spec": spec, "trace": trace, "shards": shards}


def apply_batch_migration(root: Path, plan: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    batch = plan["batch"]
    recovery = plan["trace"].get("recovery")
    actions = []
    if recovery:
        source, target = recovery
        actions.append(f"restore {target.relative_to(root.resolve())}")
        if not dry_run:
            if target.exists():
                raise RebaselineError(f"refusing to overwrite recovery target: {target}")
            atomic_write_bytes(target, source.read_bytes())
    if plan["spec"]["changed"]:
        actions.append(f"rewrite evidence/{batch}/commands.spec.json")
        if not dry_run:
            atomic_write_json(spec_path(root, batch), plan["spec"]["payload"])
    if not actions:
        actions.append("already canonical")
    return {"batch": batch, "dry_run": dry_run, "actions": actions}


def plan_traceability_finalization(root: Path, batch: str) -> dict[str, Any]:
    source = trace_path(root, batch).read_bytes()
    outputs = analyze_current_shards(root, batch)
    if outputs is None:
        return {
            "changed": False,
            "sha256": sha256_bytes(source),
            "phase": "legacy-unsharded",
            "source_bytes": source,
            "target_bytes": source,
        }
    plan = prepare_trace_plan(root, batch, outputs, require_ready=True)
    if plan["recovery"] is not None:
        raise RebaselineError(f"{batch} cannot finalize while using a legacy recovery bridge")
    return {
        "changed": bool(plan["changed"]),
        "sha256": sha256_bytes(plan["target_bytes"]),
        "phase": plan["phase"],
        "source_bytes": source,
        "target_bytes": plan["target_bytes"],
    }


def apply_traceability_finalization(root: Path, batch: str, plan: dict[str, Any]) -> None:
    path = trace_path(root, batch)
    if path.read_bytes() != plan["source_bytes"]:
        raise RebaselineError(f"{batch} traceability changed after finalization was planned")
    if plan["changed"]:
        atomic_write_bytes(path, plan["target_bytes"])


def finalize_traceability(root: Path, batch: str, *, dry_run: bool = False) -> dict[str, Any]:
    plan = plan_traceability_finalization(root, batch)
    if not dry_run:
        apply_traceability_finalization(root, batch, plan)
    return plan


def _read_command_records(root: Path, batch: str) -> list[dict[str, Any]]:
    path = root.resolve() / "evidence" / batch / "commands.ndjson"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RebaselineError(f"{batch} command log is unreadable: {exc}") from exc
    records = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RebaselineError(f"{batch} commands.ndjson line {number} is invalid") from exc
        if not isinstance(record, dict):
            raise RebaselineError(f"{batch} commands.ndjson line {number} is not an object")
        records.append(record)
    return records


def _declared_command_outputs(batch: str, entry: dict[str, Any]) -> list[str]:
    declared = entry.get("outputs", [])
    if declared is None:
        declared = []
    if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
        raise RebaselineError(f"{batch} command outputs must be an array of paths")
    tokens = _tokens(batch, entry)
    if _script_index(tokens, "scripts/test-summary.py") is not None:
        output = _option_value(batch, tokens, "--out", required=True)
        if output is not None:
            declared = [*declared, output]
    return list(dict.fromkeys(declared))


def _contained_output(root: Path, base: Path, relative: str, batch: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise RebaselineError(f"{batch} has an unsafe output path: {relative!r}")
    target = (base / relative).resolve(strict=False)
    try:
        target.relative_to(base.resolve())
    except ValueError as exc:
        raise RebaselineError(f"{batch} output path escapes the repository: {relative}") from exc
    return target


def _clean_summary(batch: str, path: Path, *, shard: str | None = None, shards: int | None = None) -> None:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise RebaselineError(f"{batch} test summary is not an object: {path}")
    if shard is not None and payload.get("shard") != shard:
        raise RebaselineError(f"{batch} partial summary {path} does not identify shard {shard}")
    if shards is not None and payload.get("shards") != shards:
        raise RebaselineError(f"{batch} merged summary {path} does not report shards={shards}")
    if payload.get("failed") != 0 or payload.get("skipped_critical") != 0:
        raise RebaselineError(f"{batch} test summary is not clean: {path}")
    if not isinstance(payload.get("run"), int) or payload.get("run") != payload.get("passed"):
        raise RebaselineError(f"{batch} test summary does not have run == passed: {path}")


def _verify_command_record_prefix(
    root: Path,
    batch: str,
    commands: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> None:
    if len(records) > len(commands):
        raise RebaselineError(
            f"{batch} command log has more records than its current specification"
        )
    spec_digest = sha256_file(spec_path(root, batch))
    base = root.resolve() / "evidence" / batch
    for index, (entry, record) in enumerate(zip(commands, records)):
        expected_exit = entry.get("expect", 0)
        if record.get("spec_index") != index or record.get("spec_sha256") != spec_digest:
            raise RebaselineError(f"{batch} command record {index} is not bound to the current spec")
        if record.get("command") != entry["command"]:
            raise RebaselineError(f"{batch} command record {index} is out of order or stale")
        if record.get("expected_exit_code") != expected_exit:
            raise RebaselineError(f"{batch} command record {index} has the wrong expected exit")
        if record.get("exit_code") != expected_exit:
            raise RebaselineError(f"{batch} command record {index} did not pass")
        output_digest = record.get("output_sha256")
        if not isinstance(output_digest, str) or HEX64.fullmatch(output_digest) is None:
            raise RebaselineError(f"{batch} command record {index} has no output digest")
        if not isinstance(record.get("output_bytes"), int) or record["output_bytes"] < 0:
            raise RebaselineError(f"{batch} command record {index} has no output size")
        save_to = entry.get("save_to")
        if not isinstance(save_to, str) or not save_to:
            raise RebaselineError(f"{batch} command {index} has no durable save_to proof")
        if record.get("saved_to") != save_to:
            raise RebaselineError(f"{batch} command record {index} saved to the wrong evidence path")
        saved = _contained_output(root, base, save_to, batch)
        if not saved.is_file():
            raise RebaselineError(f"{batch} command record {index} saved output is missing")
        saved_payload = saved.read_bytes()
        if sha256_bytes(saved_payload) != output_digest \
                or record.get("saved_output_sha256") != output_digest \
                or len(saved_payload) != record.get("output_bytes"):
            raise RebaselineError(f"{batch} command record {index} saved output proof drifted")

        produced = record.get("produced_outputs", [])
        if produced is None:
            produced = []
        if not isinstance(produced, list):
            raise RebaselineError(f"{batch} command record {index} produced_outputs is malformed")
        by_path = {
            item.get("path"): item for item in produced if isinstance(item, dict)
        }
        declared_outputs = _declared_command_outputs(batch, entry)
        if set(by_path) != set(declared_outputs):
            raise RebaselineError(f"{batch} command record {index} output proof set is incomplete")
        for relative in declared_outputs:
            target = _contained_output(root, root.resolve(), relative, batch)
            proof = by_path[relative]
            if not proof.get("fresh") or not target.is_file():
                raise RebaselineError(f"{batch} command record {index} output was not fresh: {relative}")
            payload = target.read_bytes()
            if proof.get("sha256") != sha256_bytes(payload) or proof.get("bytes") != len(payload):
                raise RebaselineError(f"{batch} command record {index} output proof drifted: {relative}")


def verified_transcript_prefix(root: Path, batch: str) -> int:
    commands = read_commands(root, batch)
    log = root.resolve() / "evidence" / batch / "commands.ndjson"
    if not log.is_file():
        return 0
    records = _read_command_records(root, batch)
    _verify_command_record_prefix(root, batch, commands, records)
    return len(records)


def verify_precompletion(root: Path, batch: str) -> dict[str, Any]:
    commands = read_commands(root, batch)
    records = _read_command_records(root, batch)
    if len(records) != len(commands):
        raise RebaselineError(
            f"{batch} command log has {len(records)} records for {len(commands)} spec commands"
        )
    _verify_command_record_prefix(root, batch, commands, records)
    outputs = analyze_current_shards(root, batch)
    if outputs is None:
        _clean_summary(
            batch, root.resolve() / f"evidence/{batch}/test-results/summary.json"
        )
        return {"commands": len(commands), "shards": None}

    shard_count = len(outputs["negative_labels"])
    for (index, count), rel in zip(outputs["negative_labels"], outputs["negative_logs"]):
        path = root.resolve() / rel
        if not _nonempty_file(path):
            raise RebaselineError(f"{batch} negative-control shard output is missing/empty: {rel}")
        text = path.read_text(encoding="utf-8", errors="replace")
        if f"shard={index}/{count}" not in text or "failures=0" not in text:
            raise RebaselineError(f"{batch} negative-control shard {index}/{count} is not successful")
    for index, rel in enumerate(outputs["partial_summaries"], 1):
        _clean_summary(
            batch,
            root.resolve() / rel,
            shard=f"{index}/{shard_count}",
        )
    for rel in outputs["partial_logs"] + outputs["summary_capture_logs"]:
        if not _nonempty_file(root.resolve() / rel):
            raise RebaselineError(f"{batch} required shard output is missing/empty: {rel}")
    _clean_summary(
        batch,
        root.resolve() / outputs["merged_summary"],
        shards=shard_count,
    )
    return {"commands": len(commands), "shards": shard_count}


def _declared_artifact_hashes(
    root: Path,
    batch: str,
    *,
    digest_overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    listing = _load_json(artifacts_path(root, batch))
    if not isinstance(listing, list) or not listing:
        raise RebaselineError(f"{batch} artifacts.json must be a non-empty array")
    result: dict[str, str] = {}
    real_root = root.resolve()
    for rel in listing:
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
            raise RebaselineError(f"{batch} has an invalid artifact path: {rel!r}")
        try:
            target = (real_root / rel).resolve(strict=True)
            target.relative_to(real_root)
        except (OSError, ValueError) as exc:
            raise RebaselineError(f"{batch} artifact is missing or escapes the repository: {rel}") from exc
        if not target.is_file():
            raise RebaselineError(f"{batch} artifact is not a regular file: {rel}")
        if rel in result:
            raise RebaselineError(f"{batch} artifacts.json repeats {rel}")
        override = (digest_overrides or {}).get(rel)
        result[rel] = override if override is not None else sha256_file(target)
    return result


def expected_review_binding(
    root: Path,
    batch: str,
    binding: dict[str, Any],
    *,
    traceability_sha256: str | None = None,
) -> dict[str, Any]:
    trace_digest = traceability_sha256 or sha256_file(trace_path(root, batch))
    if HEX64.fullmatch(trace_digest) is None:
        raise RebaselineError(f"{batch} prospective traceability digest is malformed")
    trace_relative = f"evidence/{batch}/traceability.json"
    return {
        "git_head": binding["git_head"],
        "manifest_sha256": binding["manifest_sha256"],
        "commands_spec_sha256": binding["command_spec_sha256"][batch],
        "artifacts_json_sha256": sha256_file(artifacts_path(root, batch)),
        "traceability_sha256": trace_digest,
        "artifacts": _declared_artifact_hashes(
            root, batch, digest_overrides={trace_relative: trace_digest}
        ),
    }


def review_path(root: Path, batch: str) -> Path:
    return root.resolve() / "evidence" / batch / "review.json"


def review_is_git_tracked(root: Path, path: Path) -> bool:
    try:
        real_root = root.resolve(strict=True)
        real_batch_dir = path.parent.resolve(strict=True)
        real_batch_dir.relative_to(real_root)
        resolved = path.resolve(strict=True)
        resolved.relative_to(real_batch_dir)
        relative = resolved.relative_to(real_root).as_posix()
    except (OSError, ValueError):
        return False
    if not resolved.is_file():
        return False
    proc = subprocess.run(
        ["git", "-C", str(root.resolve()), "ls-files", "--error-unmatch", "--", relative],
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


def validate_review_attestation(
    root: Path,
    batch: str,
    binding: dict[str, Any],
    *,
    traceability_sha256: str | None = None,
) -> Path:
    expected = expected_review_binding(
        root, batch, binding, traceability_sha256=traceability_sha256
    )
    path = review_path(root, batch)
    template = {
        "schema_version": "1.0.0",
        "batch_id": batch,
        "decision": "approved",
        "reviewer": "configured independent human reviewer",
        "executor": "configured implementation executor",
        "reviewed_at": "ISO-8601 timestamp with timezone",
        "scope": "non-empty review scope",
        "notes": "non-empty independent review notes",
        "bindings": expected,
    }
    if not path.is_file():
        raise ReviewBlocked(batch, f"independent review attestation is missing: {path}", template)
    if not review_is_git_tracked(root, path):
        raise ReviewBlocked(
            batch,
            "independent review attestation is outside the batch or not tracked by Git",
            template,
        )
    try:
        doc = _load_json(path)
    except RebaselineError as exc:
        raise ReviewBlocked(
            batch, f"independent review attestation is unreadable: {exc}", template
        ) from exc
    config = _load_json(root.resolve() / "governance/project-config.json")
    evidence = config.get("evidence") if isinstance(config, dict) else None
    if not isinstance(doc, dict) or not isinstance(evidence, dict):
        raise ReviewBlocked(batch, "review attestation or project evidence config is malformed", template)
    reviewer, executor = evidence.get("reviewer"), evidence.get("executor")
    reasons = []
    expected_top = {
        "schema_version", "batch_id", "decision", "reviewer", "executor",
        "reviewed_at", "scope", "notes", "bindings",
    }
    expected_binding_keys = {
        "git_head", "manifest_sha256", "commands_spec_sha256",
        "artifacts_json_sha256", "traceability_sha256", "artifacts",
    }
    if set(doc) != expected_top:
        reasons.append("top_level_keys")
    bindings = doc.get("bindings")
    if not isinstance(bindings, dict) or set(bindings) != expected_binding_keys:
        reasons.append("binding_keys")
    if doc.get("schema_version") != "1.0.0":
        reasons.append("schema_version")
    if doc.get("batch_id") != batch:
        reasons.append("batch_id")
    if doc.get("decision") != "approved":
        reasons.append("decision")
    if not isinstance(reviewer, str) or not reviewer or doc.get("reviewer") != reviewer:
        reasons.append("reviewer")
    if not isinstance(executor, str) or not executor or doc.get("executor") != executor:
        reasons.append("executor")
    if reviewer == executor:
        reasons.append("reviewer_must_differ_from_executor")
    for field in ("scope", "notes"):
        if not isinstance(doc.get(field), str) or not doc[field].strip():
            reasons.append(field)
    reviewed_at = doc.get("reviewed_at")
    try:
        parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone missing")
    except (AttributeError, ValueError):
        reasons.append("reviewed_at")
    if doc.get("bindings") != expected:
        reasons.append("bindings")
    if reasons:
        raise ReviewBlocked(
            batch,
            "independent review attestation is missing/stale in: " + ", ".join(reasons),
            template,
        )
    return path


def run_process(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=root.resolve(),
        text=True,
        capture_output=True,
        check=False,
    )


def live_validate(root: Path, batch: str) -> bool:
    """Ask the in-repository validator; never infer validity from files."""
    proc = run_process(
        root,
        [sys.executable, "scripts/batch.py", "validate", batch],
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RebaselineError(
            f"live validation for {batch} returned unreadable output (exit {proc.returncode}): "
            f"{(proc.stdout + proc.stderr)[-1200:]}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("batch") != batch:
        raise RebaselineError(f"live validation for {batch} returned the wrong batch payload")
    valid = payload.get("valid") is True
    if valid != (proc.returncode == 0):
        raise RebaselineError(
            f"live validation for {batch} disagrees with its exit code {proc.returncode}"
        )
    if proc.returncode not in (0, 2):
        raise RebaselineError(
            f"live validation for {batch} could not complete (exit {proc.returncode})"
        )
    return valid


def _finish_arguments(
    batch: str,
    start: int,
    stop: int,
    *,
    record_only: bool,
    append: bool,
    review: Path | None = None,
    root: Path,
) -> list[str]:
    arguments = [
        sys.executable,
        "scripts/finish-batch.py",
        batch,
        "--range",
        f"{start}:{stop}",
    ]
    if record_only:
        arguments.append("--record-only")
    if append:
        arguments.append("--append")
    if review is not None:
        arguments += ["--review-attestation", review.relative_to(root.resolve()).as_posix()]
    return arguments


def _run_finish(root: Path, arguments: list[str], batch: str, action: str) -> None:
    try:
        proc = run_process(root, arguments)
    except OSError as exc:
        raise RebaselineError(f"{batch} {action} could not start: {exc}") from exc
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr)[-3000:]
        raise RebaselineError(f"{batch} {action} failed with exit {proc.returncode}:\n{tail}")


def _progress_summary(state: dict[str, Any], batches: list[str], root: Path) -> dict[str, Any]:
    progress = state["progress"]
    batch_index = progress["batch_index"]
    if batch_index >= len(batches):
        return {"batch_index": batch_index, "command_index": 0, "phase": "all-recorded"}
    batch = batches[batch_index]
    count = len(read_commands(root, batch))
    command_index = progress["command_index"]
    phase = "review-boundary" if command_index == count else "commands"
    return {
        "batch_index": batch_index,
        "batch": batch,
        "command_index": command_index,
        "command_count": count,
        "command_started": progress["command_started"],
        "phase": phase,
    }


def resume_range(
    root: Path,
    batches: list[str],
    *,
    launch_window_seconds: float,
    dry_run: bool,
) -> dict[str, Any]:
    """Launch slices within the window; an atomic slice may finish later.

    Killing ``finish-batch`` at the deadline could leave its child command
    running outside the recorder, so the budget is intentionally checked only
    between transactional command slices.
    """
    binding = current_binding(root, batches)
    saved = load_state(root, binding, batches)
    state = copy.deepcopy(saved) if saved is not None else new_state(binding)
    if saved is None and not dry_run:
        save_state(root, state)
    started = time.monotonic()
    actions: list[dict[str, Any]] = []

    while state["progress"]["batch_index"] < len(batches):
        if time.monotonic() - started >= launch_window_seconds:
            return {
                "status": "paused",
                "dry_run": dry_run,
                "actions": actions,
                "progress": _progress_summary(state, batches, root),
            }
        batch_index = state["progress"]["batch_index"]
        batch = batches[batch_index]
        command_index = state["progress"]["command_index"]
        commands = read_commands(root, batch)

        # The only legal skip decision is the live local validator.  Completion
        # files, prior prose, and state indices are never treated as proof.  A
        # live-valid legacy completion still cannot bypass independent review.
        if live_validate(root, batch):
            review = validate_review_attestation(root, batch, binding)
            precompletion = verify_precompletion(root, batch)
            actions.append({
                "batch": batch,
                "action": "skip-live-valid",
                "precompletion": precompletion,
                "review": review.relative_to(root.resolve()).as_posix(),
            })
            state["progress"] = {
                "batch_index": batch_index + 1,
                "command_index": 0,
                "command_started": False,
            }
            if dry_run:
                continue
            save_state(root, state)
            continue

        if state["progress"]["command_started"]:
            prefix = verified_transcript_prefix(root, batch)
            if prefix not in (command_index, command_index + 1):
                raise StaleState(
                    f"{batch} transcript prefix {prefix} is incompatible with interrupted "
                    f"command index {command_index}"
                )
            recovered = prefix == command_index + 1
            state["progress"]["command_index"] = prefix
            state["progress"]["command_started"] = False
            actions.append({
                "batch": batch,
                "action": "recover-interrupted-command" if recovered else "retry-interrupted-command",
                "command_index": command_index,
                "transcript_prefix": prefix,
            })
            if not dry_run:
                save_state(root, state)
            if recovered:
                continue

        if command_index < len(commands):
            arguments = _finish_arguments(
                batch,
                command_index,
                command_index + 1,
                record_only=True,
                append=command_index > 0,
                root=root,
            )
            action = {
                "batch": batch,
                "action": "record-command",
                "command_index": command_index,
                "command": commands[command_index]["command"],
                "argv": arguments,
            }
            actions.append(action)
            if dry_run:
                return {
                    "status": "dry-run",
                    "dry_run": True,
                    "actions": actions,
                    "progress": _progress_summary(state, batches, root),
                }
            state["progress"]["command_started"] = True
            save_state(root, state)
            _run_finish(root, arguments, batch, f"command {command_index}")
            state["progress"]["command_index"] = command_index + 1
            state["progress"]["command_started"] = False
            save_state(root, state)
            continue

        # All commands are recorded.  Verify the exact transcript and outputs
        # before even looking for review.  A missing review leaves both trace
        # and completion untouched at this boundary.
        precompletion = verify_precompletion(root, batch)
        trace = plan_traceability_finalization(root, batch)
        review = validate_review_attestation(
            root, batch, binding, traceability_sha256=trace["sha256"]
        )
        action = {
            "batch": batch,
            "action": "finalize-reviewed-completion",
            "precompletion": precompletion,
            "review": review.relative_to(root.resolve()).as_posix(),
        }
        actions.append(action)
        if dry_run:
            action["traceability"] = {
                "phase": trace["phase"],
                "changed": trace["changed"],
                "sha256": trace["sha256"],
            }
            return {
                "status": "dry-run",
                "dry_run": True,
                "actions": actions,
                "progress": _progress_summary(state, batches, root),
            }

        apply_traceability_finalization(root, batch, trace)
        action["traceability"] = {
            "phase": trace["phase"],
            "changed": trace["changed"],
            "sha256": trace["sha256"],
        }
        final_arguments = _finish_arguments(
            batch,
            len(commands),
            len(commands),
            record_only=False,
            append=True,
            review=review,
            root=root,
        )
        try:
            _run_finish(root, final_arguments, batch, "reviewed completion")
        except RebaselineError:
            atomic_write_bytes(trace_path(root, batch), trace["source_bytes"])
            raise
        if not live_validate(root, batch):
            raise RebaselineError(f"{batch} completion was written but live validation still fails")
        state["progress"] = {
            "batch_index": batch_index + 1,
            "command_index": 0,
            "command_started": False,
        }
        save_state(root, state)

    return {
        "status": "all-done",
        "dry_run": dry_run,
        "actions": actions,
        "progress": _progress_summary(state, batches, root),
    }


def status_data(root: Path, batches: list[str]) -> dict[str, Any]:
    binding = current_binding(root, batches)
    state = load_state(root, binding, batches)
    if state is None:
        state = new_state(binding)
        source = "absent"
    else:
        source = "present"
    return {
        "state": source,
        "state_path": state_path(root).relative_to(root.resolve()).as_posix(),
        "binding": binding,
        "progress": _progress_summary(state, batches, root),
    }


def reset_state(root: Path, *, dry_run: bool) -> dict[str, Any]:
    path = state_path(root)
    existed = path.is_file()
    if existed and not dry_run:
        path.unlink()
    return {
        "status": "would-reset" if dry_run else "reset",
        "state_path": path.relative_to(root.resolve()).as_posix(),
        "existed": existed,
        "dry_run": dry_run,
    }


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return value


def _shard_count(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return value


def _add_range(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--from", dest="batch_from", metavar="BATCH")
    parser.add_argument("--to", dest="batch_to", metavar="BATCH")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely migrate, inspect, and resume payment evidence re-baselining.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="subcommand", required=True)

    status = commands.add_parser("status", allow_abbrev=False)
    _add_range(status)
    status.add_argument("--dry-run", action="store_true", help="accepted for automation symmetry")

    migrate = commands.add_parser("migrate-shards", allow_abbrev=False)
    _add_range(migrate)
    migrate.add_argument("--shards", type=_shard_count, default=DEFAULT_SHARDS)
    migrate.add_argument("--dry-run", action="store_true")

    resume = commands.add_parser("resume", allow_abbrev=False)
    _add_range(resume)
    resume.add_argument(
        "--launch-window-seconds",
        type=_positive_float,
        default=DEFAULT_LAUNCH_WINDOW_SECONDS,
        help=(
            "command-launch window; an already launched transactional command "
            "is allowed to finish safely"
        ),
    )
    resume.add_argument("--dry-run", action="store_true")

    reset = commands.add_parser("reset", allow_abbrev=False)
    reset.add_argument("--dry-run", action="store_true")
    return parser


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None, *, root: Path | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    repo = (root or ROOT).resolve()
    try:
        with state_lock(repo):
            if args.subcommand == "reset":
                _print_json(reset_state(repo, dry_run=args.dry_run))
                return 0

            batches = resolve_range(repo, args.batch_from, args.batch_to)
            if args.subcommand == "status":
                result = status_data(repo, batches)
                result["dry_run"] = bool(args.dry_run)
                _print_json(result)
                return 0

            if args.subcommand == "migrate-shards":
                if state_path(repo).is_file():
                    raise RebaselineError(
                        "resume state exists; reset it before changing command specifications"
                    )
                # Diagnose the entire range before the first write.  Ambiguous
                # partial families therefore cannot leave earlier batches changed.
                plans = [prepare_batch_migration(repo, batch, args.shards) for batch in batches]
                results = [
                    apply_batch_migration(repo, plan, dry_run=args.dry_run) for plan in plans
                ]
                _print_json({"status": "ok", "shards": args.shards, "results": results})
                return 0

            if args.subcommand == "resume":
                _print_json(
                    resume_range(
                        repo,
                        batches,
                        launch_window_seconds=args.launch_window_seconds,
                        dry_run=args.dry_run,
                    )
                )
                return 0
            raise RebaselineError(f"unknown subcommand: {args.subcommand}")
    except ReviewBlocked as exc:
        _print_json(
            {
                "status": "review-blocked",
                "batch": exc.batch,
                "reason": exc.reason,
                "expected_review": exc.expected,
            }
        )
        return 2
    except RebaselineError as exc:
        print(f"rebaseline: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
