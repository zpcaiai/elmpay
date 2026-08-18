#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((BASE / "manifest.json").read_text(encoding="utf-8"))
BATCHES = {b["id"]: b for b in MANIFEST["batches"]}
REQUIRED_COMPLETION_FIELDS = {
    "batch_id", "status", "commit_sha", "environment", "started_at", "completed_at",
    "executor", "reviewer", "artifacts", "tests", "security", "dependency_hashes",
}
HEX64 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[0-9a-fA-F]{7,64}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def completion_path(repo: Path, bid: str) -> Path:
    return repo / "evidence" / "completion" / f"{bid}.json"


def read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_completion(repo: Path, bid: str) -> dict[str, Any] | None:
    data = read_json(completion_path(repo, bid))
    return data if isinstance(data, dict) else None


def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def contained_path(repo: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return None
    try:
        candidate = (repo / relative).resolve(strict=False)
        candidate.relative_to(repo.resolve())
        return candidate
    except (ValueError, OSError):
        return None


def directory_has_evidence(path: Path) -> bool:
    return path.is_dir() and any(p.is_file() and p.stat().st_size > 0 for p in path.rglob("*"))


def validate_commands(path: Path) -> list[str]:
    problems: list[str] = []
    if not path.is_file() or path.stat().st_size == 0:
        return [f"commands evidence is empty: {path}"]
    count = 0
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        try:
            row = json.loads(line)
        except Exception:
            problems.append(f"invalid commands.ndjson line {lineno}")
            continue
        if not isinstance(row, dict):
            problems.append(f"commands.ndjson line {lineno} must be an object")
            continue
        for key in ("timestamp", "command", "exit_code"):
            if key not in row:
                problems.append(f"commands.ndjson line {lineno} missing {key}")
        if "exit_code" in row and not isinstance(row["exit_code"], int):
            problems.append(f"commands.ndjson line {lineno} exit_code must be integer")
    if count == 0:
        problems.append("commands.ndjson must contain at least one command record")
    return problems


def validate_traceability(path: Path, bid: str) -> list[str]:
    data = read_json(path)
    if not isinstance(data, dict):
        return [f"traceability is not valid JSON object: {path}"]
    problems: list[str] = []
    if data.get("batch_id") != bid:
        problems.append("traceability batch_id mismatch")
    for key in ("requirements", "code", "tests", "controls", "evidence"):
        value = data.get(key)
        if not isinstance(value, list) or not value:
            problems.append(f"traceability {key} must be a non-empty array")
    return problems


def verify_git_commit(repo: Path, commit_sha: str) -> bool:
    if not (repo / ".git").exists():
        return True
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def validate_own_evidence(repo: Path, bid: str) -> list[str]:
    batch = BATCHES[bid]
    root = repo / "evidence" / bid
    cp = completion_path(repo, bid)
    plan = root / "plan.md"
    commands = root / "commands.ndjson"
    traceability = root / "traceability.json"
    problems: list[str] = []

    if not plan.is_file() or plan.stat().st_size < 200:
        problems.append(f"plan evidence missing or too small: {plan}")
    problems.extend(validate_commands(commands))
    problems.extend(validate_traceability(traceability, bid))
    for name in ("test-results", "runtime", "security"):
        path = root / name
        if not directory_has_evidence(path):
            problems.append(f"evidence directory has no non-empty file: {path}")

    data = load_completion(repo, bid)
    if data is None:
        problems.append(f"invalid completion JSON: {cp}")
        return problems
    missing = sorted(REQUIRED_COMPLETION_FIELDS - set(data))
    if missing:
        problems.append(f"completion missing fields: {missing}")
    if data.get("batch_id") != bid:
        problems.append("completion batch_id mismatch")
    if data.get("status") != "passed":
        problems.append("completion status must be passed")

    commit_sha = data.get("commit_sha")
    if not isinstance(commit_sha, str) or not COMMIT.fullmatch(commit_sha):
        problems.append("commit_sha must be 7-64 hexadecimal characters")
    elif not verify_git_commit(repo, commit_sha):
        problems.append("commit_sha is not an existing commit in this repository")

    if not isinstance(data.get("environment"), str) or len(data["environment"].strip()) < 2:
        problems.append("environment is missing")
    started = parse_datetime(data.get("started_at"))
    completed_at = parse_datetime(data.get("completed_at"))
    if started is None or completed_at is None:
        problems.append("started_at and completed_at must be ISO-8601 timestamps")
    elif completed_at < started:
        problems.append("completed_at precedes started_at")

    executor = data.get("executor")
    reviewer = data.get("reviewer")
    if not isinstance(executor, str) or len(executor.strip()) < 2:
        problems.append("executor is missing")
    if not isinstance(reviewer, str) or len(reviewer.strip()) < 2:
        problems.append("reviewer is missing")
    if executor == reviewer:
        problems.append("executor and reviewer must differ")

    tests = data.get("tests")
    if not isinstance(tests, dict):
        problems.append("tests summary must be an object")
    elif tests.get("failed") != 0 or tests.get("skipped_critical") != 0 or not isinstance(tests.get("passed"), int) or tests.get("passed", 0) < 1:
        problems.append("test summary does not pass")

    security = data.get("security")
    if not isinstance(security, dict):
        problems.append("security summary must be an object")
    else:
        if security.get("blocking_findings") != 0:
            problems.append("blocking security findings remain")
        accepted = security.get("accepted_findings")
        if not isinstance(accepted, int) or accepted < 0:
            problems.append("accepted_findings must be a non-negative integer")
        elif accepted > 0 and not (root / "security" / "accepted-findings.json").is_file():
            problems.append("accepted findings require security/accepted-findings.json")

    dependency_hashes = data.get("dependency_hashes")
    if not isinstance(dependency_hashes, dict):
        problems.append("dependency_hashes must be an object")
    else:
        expected_deps = set(batch["depends_on"])
        if set(dependency_hashes) != expected_deps:
            problems.append(f"dependency_hashes keys must equal {sorted(expected_deps)}")
        for dep in batch["depends_on"]:
            dp = completion_path(repo, dep)
            if not dp.is_file():
                problems.append(f"dependency completion missing: {dep}")
            elif dependency_hashes.get(dep) != sha256(dp):
                problems.append(f"dependency hash mismatch: {dep}")

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        problems.append("artifacts must be a non-empty array")
    else:
        seen: set[str] = set()
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                problems.append(f"artifact {index} must be an object")
                continue
            rel = artifact.get("path")
            digest = artifact.get("sha256")
            if rel in seen:
                problems.append(f"duplicate artifact path: {rel}")
            if isinstance(rel, str):
                seen.add(rel)
            target = contained_path(repo, rel)
            if target is None:
                problems.append(f"artifact path escapes repository: {rel}")
            elif not target.is_file():
                problems.append(f"artifact missing: {rel}")
            elif not isinstance(digest, str) or not HEX64.fullmatch(digest):
                problems.append(f"artifact hash format invalid: {rel}")
            elif digest != sha256(target):
                problems.append(f"artifact hash mismatch: {rel}")

    return problems


def validate_cached(repo: Path, bid: str, cache: dict[str, tuple[bool, list[str]]]) -> tuple[bool, list[str]]:
    if bid in cache:
        return cache[bid]
    problems = validate_own_evidence(repo, bid)
    for dep in BATCHES[bid]["depends_on"]:
        dep_valid, _ = validate_cached(repo, dep, cache)
        if not dep_valid:
            problems.append(f"dependency evidence is invalid: {dep}")
    result = (not problems, problems)
    cache[bid] = result
    return result


def validate(repo: Path, bid: str, quiet: bool = False, cache: dict[str, tuple[bool, list[str]]] | None = None) -> bool:
    if bid not in BATCHES:
        raise SystemExit(f"unknown batch {bid}")
    active_cache = cache if cache is not None else {}
    valid, problems = validate_cached(repo.resolve(), bid, active_cache)
    if not quiet:
        print(json.dumps({"batch": bid, "valid": valid, "problems": problems}, ensure_ascii=False, indent=2))
    return valid


def completed(repo: Path) -> set[str]:
    cache: dict[str, tuple[bool, list[str]]] = {}
    return {b["id"] for b in MANIFEST["batches"] if validate(repo, b["id"], quiet=True, cache=cache)}


def ready(repo: Path) -> list[str]:
    done = completed(repo)
    return [b["id"] for b in MANIFEST["batches"] if b["id"] not in done and all(d in done for d in b["depends_on"])]


def init_evidence(repo: Path, bid: str):
    if bid not in BATCHES:
        raise SystemExit(f"unknown batch {bid}")
    repo = repo.resolve()
    current_ready = ready(repo)
    if bid not in current_ready and bid not in completed(repo):
        raise SystemExit(f"{bid} is not ready; ready={current_ready}")
    root = repo / "evidence" / bid
    for sub in ("test-results", "runtime", "security"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (repo / "evidence" / "completion").mkdir(parents=True, exist_ok=True)
    templates = {
        root / "plan.md": (
            f"# {bid} plan\n\nBatch: {BATCHES[bid]['title']}\n\n"
            "Record scope, affected components, commands, rollback, tests, threat changes, data migration, observability, evidence and independent reviewer.\n"
        ),
        root / "commands.ndjson": "",
        root / "traceability.json": json.dumps(
            {"batch_id": bid, "requirements": [], "code": [], "tests": [], "controls": [], "evidence": []},
            ensure_ascii=False,
            indent=2,
        ),
        root / "completion.template.json": json.dumps(
            {
                "batch_id": bid,
                "status": "passed",
                "commit_sha": "replace-with-commit-sha",
                "environment": "integration",
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:01Z",
                "executor": "implementation-owner",
                "reviewer": "independent-reviewer",
                "artifacts": [{"path": "replace-with-relative-path", "sha256": "replace-with-sha256"}],
                "tests": {"passed": 1, "failed": 0, "skipped_critical": 0},
                "security": {"blocking_findings": 0, "accepted_findings": 0},
                "dependency_hashes": {dep: "replace-with-completion-file-sha256" for dep in BATCHES[bid]["depends_on"]},
            },
            ensure_ascii=False,
            indent=2,
        ),
    }
    for path, content in templates.items():
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    print(root)


def command_status(repo: Path):
    done = completed(repo)
    print(json.dumps({"completed": len(done), "total": len(BATCHES), "ready": ready(repo), "remaining": len(BATCHES) - len(done)}, ensure_ascii=False, indent=2))


def command_prompt(repo: Path, bid: str):
    if bid not in BATCHES:
        raise SystemExit(f"unknown batch {bid}")
    current_ready = ready(repo)
    if bid not in current_ready and bid not in completed(repo):
        raise SystemExit(f"{bid} is not ready; ready={current_ready}")
    doc = (BASE / "batches" / f"{bid}.md").read_text(encoding="utf-8")
    print(f"Use skill `{BATCHES[bid]['skill']}`. Implement batch {bid} in repository {repo.resolve()}.\n")
    print(doc)


def command_release(repo: Path):
    cache: dict[str, tuple[bool, list[str]]] = {}
    invalid = [b["id"] for b in MANIFEST["batches"] if not validate(repo, b["id"], quiet=True, cache=cache)]
    result = {"release_ready": not invalid, "invalid_batches": invalid, "completed": len(BATCHES) - len(invalid), "total": len(BATCHES)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if not invalid else 2)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("status", "ready", "release"):
        command = sub.add_parser(name)
        command.add_argument("--repo", default=".")
    command = sub.add_parser("prompt")
    command.add_argument("batch")
    command.add_argument("--repo", default=".")
    command = sub.add_parser("init")
    command.add_argument("batch")
    command.add_argument("--repo", default=".")
    command = sub.add_parser("validate")
    command.add_argument("batch")
    command.add_argument("--repo", default=".")
    sub.add_parser("list")
    args = parser.parse_args()
    repo = Path(getattr(args, "repo", ".")).resolve()
    if args.cmd == "status":
        command_status(repo)
    elif args.cmd == "ready":
        print("\n".join(ready(repo)))
    elif args.cmd == "prompt":
        command_prompt(repo, args.batch)
    elif args.cmd == "init":
        init_evidence(repo, args.batch)
    elif args.cmd == "validate":
        raise SystemExit(0 if validate(repo, args.batch) else 2)
    elif args.cmd == "release":
        command_release(repo)
    elif args.cmd == "list":
        for batch in MANIFEST["batches"]:
            print(f"{batch['id']}\t{batch['skill']}\t{batch['title']}")


if __name__ == "__main__":
    main()
