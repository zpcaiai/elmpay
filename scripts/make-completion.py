#!/usr/bin/env python3
"""Atomically generate a review-bound batch completion file.

The payload is derived from live repository state, compared with the explicit
independent-review binding, atomically installed, and then checked once more.
If HEAD or any reviewed input moves during that boundary, the previous
completion is restored (or the newly-created file is removed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BATCH_ID = re.compile(r"^B[0-9]{2,3}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head() -> str:
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip().lower()


def _contained(relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError(f"unsafe repository-relative path: {relative!r}")
    target = (ROOT / relative).resolve(strict=False)
    target.relative_to(ROOT.resolve())
    return target


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _remove_durably(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _artifact_paths(path: Path) -> list[str]:
    value = _load_json(path)
    if not isinstance(value, list) or not value \
            or not all(isinstance(item, str) and item for item in value) \
            or len(value) != len(set(value)):
        raise ValueError("artifacts.json must be a non-empty array of unique paths")
    for relative in value:
        target = _contained(relative)
        if not target.is_file():
            raise ValueError(f"artifact is not a file: {relative}")
    return value


def _binding_snapshot(batch: str, spec: Path, artifacts_path: Path) -> tuple[dict, list[str]]:
    manifest = ROOT / ".payment-platform/skill-package/manifest.json"
    traceability = ROOT / "evidence" / batch / "traceability.json"
    declared = _artifact_paths(artifacts_path)
    binding = {
        "git_head": git_head(),
        "manifest_sha256": sha256(manifest),
        "commands_spec_sha256": sha256(spec),
        "artifacts_json_sha256": sha256(artifacts_path),
        "traceability_sha256": sha256(traceability),
        "artifacts": {relative: sha256(_contained(relative)) for relative in declared},
    }
    return binding, declared


def _review_binding(path: Path, batch: str, evidence_cfg: dict) -> tuple[dict, str]:
    base = (ROOT / "evidence" / batch).resolve()
    resolved = path.resolve(strict=True)
    resolved.relative_to(base)
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch",
                              "--", relative], capture_output=True, text=True, check=False)
    if tracked.returncode != 0:
        raise ValueError("review attestation must be tracked by Git")
    review_bytes = resolved.read_bytes()
    review = json.loads(review_bytes)
    top_level = {"schema_version", "batch_id", "decision", "reviewer", "executor",
                 "reviewed_at", "scope", "notes", "bindings"}
    if not isinstance(review, dict) or set(review) != top_level:
        raise ValueError("review attestation top-level schema is malformed")
    if review.get("schema_version") != "1.0.0" \
            or review.get("batch_id") != batch or review.get("decision") != "approved":
        raise ValueError("review attestation does not approve this batch")
    if review.get("executor") != evidence_cfg.get("executor") \
            or review.get("reviewer") != evidence_cfg.get("reviewer") \
            or review.get("executor") == review.get("reviewer"):
        raise ValueError("review principals do not match configured four-eyes identities")
    if not isinstance(review.get("scope"), str) or not review["scope"].strip():
        raise ValueError("review scope must be non-empty")
    if not isinstance(review.get("notes"), str) or not review["notes"].strip():
        raise ValueError("review notes must be non-empty")
    try:
        reviewed_at = datetime.fromisoformat(
            review.get("reviewed_at", "").replace("Z", "+00:00"))
        if reviewed_at.tzinfo is None or reviewed_at.utcoffset() is None:
            raise ValueError("timestamp has no UTC offset")
    except (AttributeError, ValueError) as exc:
        raise ValueError("reviewed_at must be ISO-8601 with timezone") from exc
    binding = review.get("bindings")
    expected = {"git_head", "manifest_sha256", "commands_spec_sha256",
                "artifacts_json_sha256", "traceability_sha256", "artifacts"}
    if not isinstance(binding, dict) or set(binding) != expected:
        raise ValueError("review bindings are malformed")
    return binding, hashlib.sha256(review_bytes).hexdigest()


def _dependency_hashes(batch: str, batches: dict[str, dict]) -> dict[str, str]:
    return {
        dependency: sha256(ROOT / "evidence/completion" / f"{dependency}.json")
        for dependency in batches[batch]["depends_on"]
    }


def _rollback(path: Path, previous: bytes | None) -> None:
    if previous is None:
        _remove_durably(path)
    else:
        _atomic_write(path, previous)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("batch")
    parser.add_argument("--artifacts", required=True,
                        help="path to a JSON array of repository-relative artefact paths")
    parser.add_argument("--review-attestation", required=True,
                        help="tracked review approving the exact completion inputs")
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--tests-passed", type=int, required=True)
    parser.add_argument("--accepted-findings", type=int, default=0)
    args = parser.parse_args(argv)

    if BATCH_ID.fullmatch(args.batch) is None:
        print("invalid batch id")
        return 2
    if args.tests_passed < 1 or args.accepted_findings < 0:
        print("tests-passed must be positive and accepted-findings non-negative")
        return 2

    batch = args.batch
    spec = ROOT / "evidence" / batch / "commands.spec.json"
    try:
        artifacts_path = _contained(args.artifacts)
        expected_artifacts = (ROOT / "evidence" / batch / "artifacts.json").resolve()
        if artifacts_path != expected_artifacts:
            raise ValueError("--artifacts must name this batch's artifacts.json")
        review_path = _contained(args.review_attestation)
        config = _load_json(ROOT / "governance/project-config.json")
        evidence_cfg = config["evidence"]
        manifest = _load_json(ROOT / ".payment-platform/skill-package/manifest.json")
        batches = {item["id"]: item for item in manifest["batches"]}
        if batch not in batches:
            raise ValueError(f"batch is absent from manifest: {batch}")
        approved, review_sha256 = _review_binding(review_path, batch, evidence_cfg)
        before, declared = _binding_snapshot(batch, spec, artifacts_path)
        if before != approved:
            raise ValueError("live HEAD or reviewed input hashes do not match review binding")
        dependency_hashes = _dependency_hashes(batch, batches)
    except (OSError, KeyError, ValueError, json.JSONDecodeError,
            subprocess.CalledProcessError) as exc:
        print(f"completion refused: {exc}")
        return 2

    payload = {
        "batch_id": batch,
        "status": "passed",
        "commit_sha": before["git_head"],
        "environment": evidence_cfg["environment"],
        "started_at": args.started_at,
        "completed_at": args.completed_at,
        "executor": evidence_cfg["executor"],
        "reviewer": evidence_cfg["reviewer"],
        "artifacts": [{"path": relative, "sha256": before["artifacts"][relative]}
                      for relative in declared],
        "tests": {"passed": args.tests_passed, "failed": 0, "skipped_critical": 0},
        "security": {"blocking_findings": 0,
                     "accepted_findings": args.accepted_findings},
        "dependency_hashes": dependency_hashes,
    }
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    out = ROOT / "evidence/completion" / f"{batch}.json"
    previous = out.read_bytes() if out.is_file() else None
    try:
        _atomic_write(out, encoded)
        after, after_declared = _binding_snapshot(batch, spec, artifacts_path)
        after_dependencies = _dependency_hashes(batch, batches)
        after_approved, after_review_sha256 = _review_binding(
            review_path, batch, evidence_cfg)
        if after != approved or after != before or after_declared != declared:
            raise ValueError("reviewed HEAD or artifacts changed at completion boundary")
        if after_dependencies != dependency_hashes:
            raise ValueError("dependency completions changed at completion boundary")
        if after_approved != approved or after_review_sha256 != review_sha256:
            raise ValueError("review attestation changed at completion boundary")
    except (OSError, ValueError, json.JSONDecodeError,
            subprocess.CalledProcessError) as exc:
        try:
            _rollback(out, previous)
        except OSError as rollback_error:
            print(f"completion refused and rollback failed: {exc}; {rollback_error}")
            return 2
        print(f"completion refused; previous state restored: {exc}")
        return 2

    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
