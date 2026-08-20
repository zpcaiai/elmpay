"""B06 — in-repository batch orchestration: DAG, ready set, completion, release gate.

The programme ships an orchestrator under ``.payment-platform/skill-package``.
That script is a *vendored input*: it can be replaced or removed, and it is not
covered by this repository's tests. B06 therefore owns an independent
implementation here, and the test suite runs the two against each other on every
commit (``tools/tests/test_b06_orchestration.py``). Two implementations that
disagree are a defect in one of them; one implementation that nobody checks is a
single point of failure for every release gate.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .repo import Budget, load_json

MANIFEST = Path(".payment-platform/skill-package/manifest.json")
COMPLETION_DIR = Path("evidence/completion")
PROJECT_CONFIG = Path("governance/project-config.json")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[0-9a-fA-F]{7,64}$")
REVIEW_COMMIT = re.compile(r"^[a-f0-9]{7,64}$")
REVIEW_FIELDS = {
    "schema_version", "batch_id", "decision", "reviewer", "executor",
    "reviewed_at", "scope", "notes", "bindings",
}
REVIEW_BINDING_FIELDS = {
    "git_head", "manifest_sha256", "commands_spec_sha256",
    "artifacts_json_sha256", "traceability_sha256", "artifacts",
}
REQUIRED_COMPLETION_FIELDS = {
    "batch_id", "status", "commit_sha", "environment", "started_at", "completed_at",
    "executor", "reviewer", "artifacts", "tests", "security", "dependency_hashes",
}
REQUIRED_EVIDENCE_DIRS = ("test-results", "runtime", "security")
MIN_PLAN_BYTES = 200


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Programme:
    """The batch DAG plus everything needed to decide whether a batch is done."""

    def __init__(self, root: Path, budget: Budget | None = None) -> None:
        self.root = root.resolve()
        budget = budget or Budget(seconds=120).start()
        manifest = load_json(self.root / MANIFEST, budget)
        self.batches: dict[str, dict] = {b["id"]: b for b in manifest["batches"]}
        self.order: list[str] = [b["id"] for b in manifest["batches"]]

    # ---- graph -----------------------------------------------------------
    def dependencies(self, batch: str) -> list[str]:
        return list(self.batches[batch]["depends_on"])

    def unknown_dependencies(self) -> list[tuple[str, str]]:
        return [(bid, dep) for bid in self.order
                for dep in self.dependencies(bid) if dep not in self.batches]

    def cycles(self) -> list[list[str]]:
        WHITE, GREY, BLACK = 0, 1, 2
        colour = {bid: WHITE for bid in self.order}
        found: list[list[str]] = []

        def visit(node: str, path: list[str]) -> None:
            colour[node] = GREY
            for dep in self.dependencies(node):
                if dep not in self.batches:
                    continue
                if colour[dep] == GREY:
                    found.append(path + [dep])
                elif colour[dep] == WHITE:
                    visit(dep, path + [dep])
            colour[node] = BLACK

        for bid in self.order:
            if colour[bid] == WHITE:
                visit(bid, [bid])
        return found

    def topological_order(self) -> list[str]:
        """Manifest order must already be a valid topological order."""
        seen: set[str] = set()
        result: list[str] = []
        for bid in self.order:
            result.append(bid)
            seen.add(bid)
        return result

    def manifest_is_topologically_sorted(self) -> bool:
        seen: set[str] = set()
        for bid in self.order:
            if any(dep not in seen for dep in self.dependencies(bid)):
                return False
            seen.add(bid)
        return True

    # ---- completion ------------------------------------------------------
    def completion_path(self, batch: str) -> Path:
        return self.root / COMPLETION_DIR / f"{batch}.json"

    def problems(self, batch: str, *, extended: bool = True) -> list[str]:
        """Every reason ``batch`` may not be considered complete.

        ``extended=False`` restricts the checks to the ones the vendored
        orchestrator also performs, so the differential cross-check compares
        like with like. The extra local checks (recorded exit codes,
        runner-vs-completion agreement) are strictly additional: they can make a
        batch fail here that would pass there, never the reverse, and
        ``scripts/batch.py crosscheck`` reports them separately.
        """
        if batch not in self.batches:
            return [f"unknown batch {batch}"]
        problems: list[str] = []
        base = self.root / "evidence" / batch

        plan = base / "plan.md"
        if not plan.is_file() or plan.stat().st_size < MIN_PLAN_BYTES:
            problems.append(f"plan evidence missing or too small: {plan}")
        problems += self._commands(base / "commands.ndjson")
        problems += self._traceability(base / "traceability.json", batch)
        for name in REQUIRED_EVIDENCE_DIRS:
            directory = base / name
            if not (directory.is_dir()
                    and any(p.is_file() and p.stat().st_size > 0 for p in directory.rglob("*"))):
                problems.append(f"evidence directory has no non-empty file: {directory}")

        path = self.completion_path(batch)
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return problems + [f"invalid completion JSON: {path}"]
        if not isinstance(data, dict):
            return problems + [f"invalid completion JSON: {path}"]

        missing = sorted(REQUIRED_COMPLETION_FIELDS - set(data))
        if missing:
            problems.append(f"completion missing fields: {missing}")
        if data.get("batch_id") != batch:
            problems.append("completion batch_id mismatch")
        if data.get("status") != "passed":
            problems.append("completion status must be passed")

        commit = data.get("commit_sha")
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            problems.append("commit_sha must be 7-64 hexadecimal characters")
        elif not self._commit_exists(commit):
            problems.append("commit_sha is not an existing commit in this repository")

        problems += self._principals(data)
        problems += self._timestamps(data)
        problems += self._tests(data)
        problems += self._security(data, base)
        problems += self._dependency_hashes(data, batch)
        problems += self._artifacts(data)
        if extended:
            problems += self._recorded_exit_codes(base)
            problems += self._declared_commands_ran(base)
            problems += self._summary_agreement(base, data)
            problems += self._declared_artifacts(base, data)
            problems += self._review_attestation(base, batch, data)
        return problems

    @staticmethod
    def _declared_artifacts(base: Path, data: dict) -> list[str]:
        """``artifacts.json`` and the completion file must list the same set."""
        listing = base / "artifacts.json"
        if not listing.is_file():
            return []
        try:
            declared = set(json.loads(listing.read_text(encoding="utf-8")))
        except Exception as exc:
            return [f"artifacts.json is unreadable: {exc}"]
        recorded = {a.get("path") for a in data.get("artifacts", []) if isinstance(a, dict)}
        problems = [f"artefact declared but not recorded in the completion file: {rel}"
                    for rel in sorted(declared - recorded)]
        problems += [f"artefact recorded but not declared in artifacts.json: {rel}"
                     for rel in sorted(recorded - declared)]
        return problems

    def extended_only_problems(self, batch: str) -> list[str]:
        """Findings this implementation makes that the vendored one cannot."""
        base = self.root / "evidence" / batch
        path = self.completion_path(batch)
        if not path.is_file():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        return (self._recorded_exit_codes(base) + self._declared_commands_ran(base)
                + self._summary_agreement(base, payload)
                + self._declared_artifacts(base, payload)
                + self._review_attestation(base, batch, payload))

    def _review_attestation(self, base: Path, batch: str, completion: dict) -> list[str]:
        """Revalidate the independent approval against live local evidence.

        This is deliberately an extended-only check: the vendored orchestrator
        predates review attestations.  Authoritative local status and release
        readiness use it, while the differential view can still compare the
        common upstream contract with ``extended=False``.
        """
        review_path = base / "review.json"
        try:
            resolved_base = base.resolve(strict=True)
            resolved = review_path.resolve(strict=True)
            resolved.relative_to(resolved_base)
            if review_path.is_symlink() or resolved != review_path.absolute():
                raise ValueError("review.json must be a regular in-place file")
        except (OSError, ValueError):
            return [f"review attestation is missing or outside its batch directory: {review_path}"]
        if not resolved.is_file():
            return [f"review attestation is missing or outside its batch directory: {review_path}"]

        problems: list[str] = []
        relative = review_path.relative_to(self.root).as_posix()
        try:
            tracked = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "--error-unmatch", "--",
                 relative],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15, check=False)
            if tracked.returncode != 0:
                problems.append("review attestation must be tracked by Git")
        except (OSError, subprocess.TimeoutExpired):
            problems.append("review attestation Git tracking could not be proven")

        try:
            review: Any = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return problems + [f"review attestation is unreadable: {exc}"]
        if not isinstance(review, dict):
            return problems + ["review attestation must be an object"]
        if set(review) != REVIEW_FIELDS:
            problems.append(
                f"review attestation keys must be exactly {sorted(REVIEW_FIELDS)}")
        if review.get("schema_version") != "1.0.0":
            problems.append("review schema_version must be 1.0.0")
        if review.get("batch_id") != batch or review.get("decision") != "approved":
            problems.append("review must approve the current batch")

        try:
            config: Any = json.loads(
                (self.root / PROJECT_CONFIG).read_text(encoding="utf-8"))
            identities = config["evidence"]
            if not isinstance(identities, dict):
                raise ValueError("evidence configuration must be an object")
            configured_executor = identities["executor"]
            configured_reviewer = identities["reviewer"]
            if not all(isinstance(value, str) and value.strip()
                       for value in (configured_executor, configured_reviewer)):
                raise ValueError("configured identities must be non-empty strings")
            if configured_executor == configured_reviewer:
                raise ValueError("configured executor and reviewer must differ")
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return problems + [f"cannot load configured evidence identities: {exc}"]
        if review.get("executor") != configured_executor \
                or review.get("reviewer") != configured_reviewer:
            problems.append("review principals do not match project configuration")
        if review.get("executor") == review.get("reviewer"):
            problems.append("reviewer and executor must differ")
        if not isinstance(review.get("scope"), str) or not review["scope"].strip():
            problems.append("review scope must be non-empty")
        if not isinstance(review.get("notes"), str) or not review["notes"].strip():
            problems.append("review notes must be a non-empty string")
        try:
            reviewed_at = datetime.fromisoformat(
                review.get("reviewed_at", "").replace("Z", "+00:00"))
            if reviewed_at.tzinfo is None or reviewed_at.utcoffset() is None:
                raise ValueError("timestamp has no UTC offset")
        except (AttributeError, ValueError):
            problems.append("reviewed_at must be an ISO-8601 timestamp with timezone")

        bindings = review.get("bindings")
        if not isinstance(bindings, dict):
            return problems + ["review bindings must be an object"]
        if set(bindings) != REVIEW_BINDING_FIELDS:
            problems.append(
                f"review binding keys must be exactly {sorted(REVIEW_BINDING_FIELDS)}")

        artifacts_path = base / "artifacts.json"
        try:
            declared: Any = json.loads(artifacts_path.read_text(encoding="utf-8"))
            if not isinstance(declared, list) or not declared \
                    or not all(isinstance(item, str) and item for item in declared) \
                    or len(declared) != len(set(declared)):
                raise ValueError("artifacts.json must be a non-empty array of unique paths")
            artifact_hashes: dict[str, str] = {}
            for relative in declared:
                target = self._contained(relative)
                if target is None or not target.is_file():
                    raise ValueError(f"artifact is not a contained file: {relative}")
                artifact_hashes[relative] = sha256(target)
            expected = {
                "manifest_sha256": sha256(self.root / MANIFEST),
                "commands_spec_sha256": sha256(base / "commands.spec.json"),
                "artifacts_json_sha256": sha256(artifacts_path),
                "traceability_sha256": sha256(base / "traceability.json"),
                "artifacts": artifact_hashes,
            }
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return problems + [f"cannot compute review bindings: {exc}"]

        commit = bindings.get("git_head")
        if not isinstance(commit, str) or REVIEW_COMMIT.fullmatch(commit) is None \
                or commit != completion.get("commit_sha"):
            problems.append("review binding git_head does not match completion commit_sha")
        for key in ("manifest_sha256", "commands_spec_sha256", "artifacts_json_sha256",
                    "traceability_sha256"):
            value = bindings.get(key)
            if not isinstance(value, str) or HEX64.fullmatch(value) is None \
                    or value != expected[key]:
                problems.append(f"review binding {key} does not match current evidence")
        if bindings.get("artifacts") != expected["artifacts"]:
            problems.append("review artifact hash set does not exactly match artifacts.json")
        return problems

    @staticmethod
    def _declared_commands_ran(base: Path) -> list[str]:
        """Every command the spec declares must appear in the recorded log."""
        ndjson, spec_path = base / "commands.ndjson", base / "commands.spec.json"
        if not ndjson.is_file() or not spec_path.is_file():
            return []
        try:
            recorded = {json.loads(line)["command"] for line in
                        ndjson.read_text(encoding="utf-8").splitlines() if line.strip()}
            declared = {c["command"] for c in
                        json.loads(spec_path.read_text(encoding="utf-8"))["commands"]}
        except Exception as exc:
            return [f"command log or spec is unreadable: {exc}"]
        return [f"declared command was never executed: {command}"
                for command in sorted(declared - recorded)]

    @staticmethod
    def _recorded_exit_codes(base: Path) -> list[str]:
        """The vendored orchestrator only requires exit_code to be an integer.

        A batch whose every recorded command failed would therefore validate.
        Here each record must have matched the exit code its spec expected.
        """
        ndjson = base / "commands.ndjson"
        if not ndjson.is_file():
            return []
        problems: list[str] = []
        for index, line in enumerate(ndjson.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue
            expected = record.get("expected_exit_code")
            if expected is None:
                problems.append(f"commands.ndjson record {index} has no expected_exit_code")
            elif record.get("exit_code") != expected:
                problems.append(
                    f"recorded command exited {record.get('exit_code')} but {expected} was "
                    f"expected: {record.get('command', '?')}")
        return problems

    @staticmethod
    def _summary_agreement(base: Path, data: dict) -> list[str]:
        """The completion file's test numbers must be the runner's numbers."""
        summary_path = base / "test-results" / "summary.json"
        if not summary_path.is_file():
            return ["test-results/summary.json is missing; the tests figure would be unverifiable"]
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return [f"test-results/summary.json is unreadable: {exc}"]
        problems: list[str] = []
        tests = data.get("tests", {}) if isinstance(data.get("tests"), dict) else {}
        if summary.get("failed") or summary.get("skipped_critical"):
            problems.append(f"runner summary is not clean: {summary}")
        if summary.get("run") != summary.get("passed"):
            problems.append(
                f"runner reports run={summary.get('run')} passed={summary.get('passed')}")
        if tests.get("passed") != summary.get("passed"):
            problems.append(
                f"completion records {tests.get('passed')} passing tests but the runner produced "
                f"{summary.get('passed')}")
        return problems

    def _commit_exists(self, commit: str) -> bool:
        if not (self.root / ".git").exists():
            return True
        try:
            proc = subprocess.run(["git", "-C", str(self.root), "cat-file", "-e",
                                   f"{commit}^{{commit}}"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=15, check=False)
            return proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _commands(path: Path) -> list[str]:
        if not path.is_file() or path.stat().st_size == 0:
            return [f"commands evidence is empty: {path}"]
        problems: list[str] = []
        count = 0
        for lineno, line in enumerate(path.read_text(encoding="utf-8",
                                                     errors="replace").splitlines(), 1):
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

    @staticmethod
    def _traceability(path: Path, batch: str) -> list[str]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return [f"traceability is not valid JSON object: {path}"]
        if not isinstance(data, dict):
            return [f"traceability is not valid JSON object: {path}"]
        problems: list[str] = []
        if data.get("batch_id") != batch:
            problems.append("traceability batch_id mismatch")
        for key in ("requirements", "code", "tests", "controls", "evidence"):
            value = data.get(key)
            if not isinstance(value, list) or not value:
                problems.append(f"traceability {key} must be a non-empty array")
        return problems

    @staticmethod
    def _principals(data: dict) -> list[str]:
        problems: list[str] = []
        executor, reviewer = data.get("executor"), data.get("reviewer")
        if not isinstance(data.get("environment"), str) or len(data["environment"].strip()) < 2:
            problems.append("environment is missing")
        if not isinstance(executor, str) or len(executor.strip()) < 2:
            problems.append("executor is missing")
        if not isinstance(reviewer, str) or len(reviewer.strip()) < 2:
            problems.append("reviewer is missing")
        if executor == reviewer:
            problems.append("executor and reviewer must differ")
        return problems

    @staticmethod
    def _timestamps(data: dict) -> list[str]:
        def parse(value: Any) -> datetime | None:
            if not isinstance(value, str):
                return None
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None

        started, completed = parse(data.get("started_at")), parse(data.get("completed_at"))
        if started is None or completed is None:
            return ["started_at and completed_at must be ISO-8601 timestamps"]
        if completed < started:
            return ["completed_at precedes started_at"]
        return []

    @staticmethod
    def _tests(data: dict) -> list[str]:
        tests = data.get("tests")
        if not isinstance(tests, dict):
            return ["tests summary must be an object"]
        if tests.get("failed") != 0 or tests.get("skipped_critical") != 0 \
                or not isinstance(tests.get("passed"), int) or tests.get("passed", 0) < 1:
            return ["test summary does not pass"]
        return []

    @staticmethod
    def _security(data: dict, base: Path) -> list[str]:
        security = data.get("security")
        if not isinstance(security, dict):
            return ["security summary must be an object"]
        problems: list[str] = []
        if security.get("blocking_findings") != 0:
            problems.append("blocking security findings remain")
        accepted = security.get("accepted_findings")
        if not isinstance(accepted, int) or accepted < 0:
            problems.append("accepted_findings must be a non-negative integer")
        elif accepted > 0 and not (base / "security" / "accepted-findings.json").is_file():
            problems.append("accepted findings require security/accepted-findings.json")
        return problems

    def _dependency_hashes(self, data: dict, batch: str) -> list[str]:
        hashes = data.get("dependency_hashes")
        if not isinstance(hashes, dict):
            return ["dependency_hashes must be an object"]
        problems: list[str] = []
        expected = set(self.dependencies(batch))
        if set(hashes) != expected:
            problems.append(f"dependency_hashes keys must equal {sorted(expected)}")
        for dep in self.dependencies(batch):
            path = self.completion_path(dep)
            if not path.is_file():
                problems.append(f"dependency completion missing: {dep}")
            elif hashes.get(dep) != sha256(path):
                problems.append(f"dependency hash mismatch: {dep}")
        return problems

    def _artifacts(self, data: dict) -> list[str]:
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return ["artifacts must be a non-empty array"]
        problems: list[str] = []
        seen: set[str] = set()
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                problems.append(f"artifact {index} must be an object")
                continue
            rel, digest = artifact.get("path"), artifact.get("sha256")
            if rel in seen:
                problems.append(f"duplicate artifact path: {rel}")
            if isinstance(rel, str):
                seen.add(rel)
            target = self._contained(rel)
            if target is None:
                problems.append(f"artifact path escapes repository: {rel}")
            elif not target.is_file():
                problems.append(f"artifact missing: {rel}")
            elif not isinstance(digest, str) or not HEX64.fullmatch(digest):
                problems.append(f"artifact hash format invalid: {rel}")
            elif digest != sha256(target):
                problems.append(f"artifact hash mismatch: {rel}")
        return problems

    def _contained(self, relative: Any) -> Path | None:
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            return None
        try:
            candidate = (self.root / relative).resolve(strict=False)
            candidate.relative_to(self.root)
            return candidate
        except (ValueError, OSError):
            return None

    # ---- derived state ---------------------------------------------------
    def valid(self, batch: str, cache: dict[str, bool] | None = None, *,
              extended: bool = True) -> bool:
        cache = {} if cache is None else cache
        if batch in cache:
            return cache[batch]
        cache[batch] = False  # guards against cyclic manifests
        ok = not self.problems(batch, extended=extended) and all(
            self.valid(dep, cache, extended=extended) for dep in self.dependencies(batch))
        cache[batch] = ok
        return ok

    def completed(self, *, extended: bool = True) -> set[str]:
        cache: dict[str, bool] = {}
        return {bid for bid in self.order if self.valid(bid, cache, extended=extended)}

    def ready(self, *, extended: bool = True) -> list[str]:
        done = self.completed(extended=extended)
        return [bid for bid in self.order
                if bid not in done and all(dep in done for dep in self.dependencies(bid))]

    def status(self, *, extended: bool = True) -> dict:
        done = self.completed(extended=extended)
        return {"completed": len(done), "total": len(self.batches),
                "ready": self.ready(extended=extended),
                "remaining": len(self.batches) - len(done)}

    def release_ready(self, *, extended: bool = True) -> dict:
        done = self.completed(extended=extended)
        invalid = [bid for bid in self.order if bid not in done]
        return {"release_ready": not invalid, "invalid_batches": invalid,
                "completed": len(done), "total": len(self.batches)}
