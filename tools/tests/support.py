"""Fixture helpers: build a disposable copy of the governance surface.

Negative tests must be able to corrupt configuration without touching the real
repository, so every mutation test runs against a temporary clone that contains
only the files the validators read.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.paygov import catalogue
from tools.paygov.repo import repo_root

REAL_ROOT = repo_root(Path(__file__).resolve())

# Discovered, not enumerated. Every batch adds a governance source and a
# contracts/libs artefact; listing them by hand meant editing this file in every
# batch, which invalidated the artefact hash of the batch that owns it and forced
# a full re-baseline of the entire programme each time. Describing the *kind* of
# input instead of each instance keeps this file stable, and a new governance
# file becomes part of every fixture automatically rather than when somebody
# remembers.
def _discovered() -> tuple:
    found: list[str] = []
    for pattern in ("governance/*.json", "contracts/**/*.json", "contracts/**/*.sql",
                    "libs/**/*.py"):
        for path in sorted(REAL_ROOT.glob(pattern)):
            if path.is_file():
                found.append(path.relative_to(REAL_ROOT).as_posix())
    return tuple(dict.fromkeys(found))


COPIED_FILES = _discovered() + (
    "docs/charter/PROGRAM_CHARTER.md",
    "docs/charter/RISK_ACCEPTANCE_POLICY.md",
    "docs/charter/DELIVERY_MODEL.md",
    "docs/requirements/REQUIREMENTS_BASELINE.md",
    "docs/requirements/SERVICE_BOUNDARIES.md",
    ".payment-platform/skill-package/policies/non-negotiables.md",
    ".payment-platform/skill-package/security/THREAT_MODEL.md",
    ".payment-platform/skill-package/manifest.json",
    ".payment-platform/skill-package/compliance/controls-matrix.csv",
)

# Whole trees, discovered rather than enumerated. A hand-written list of doc
# directories meant every batch that added one had to edit this file — and this
# file is an artefact of B00, so that edit invalidated B00 and cascaded a full
# programme re-baseline. Same reasoning as the governance/contracts globs above.
COPIED_DIRS = ("docs", "contracts")

# Generated build files: the toolchain validator compares them against the
# catalogue, so a fixture must carry them too.
GENERATED_BUILD_FILES = (
    "gradle/libs.versions.toml",
    "settings.gradle.kts",
    "build.gradle.kts",
    ".tool-versions",
    "platform/toolchain/versions.env",
    "platform/dev/compose.yaml",
    "platform/dev/.env.example",
    "platform/dev/README.md",
    "platform/dev/simulators/wechat/Dockerfile",
    "platform/dev/simulators/alipay/Dockerfile",
    "platform/dev/simulators/stripe/Dockerfile",
    "platform/dev/simulators/paypal/Dockerfile",
    "platform/dev/simulators/apple-pay/Dockerfile",
    ".github/workflows/ci.yml",
    "scripts/sign-artifacts.sh",
)


def _snapshot() -> dict[str, bytes]:
    """Read every fixture input once.

    The repository lives on a slow mount and the suite builds a fresh fixture
    per test; reading the sources once and writing from memory keeps the suite
    fast without weakening isolation.
    """
    blobs: dict[str, bytes] = {}
    for rel in COPIED_FILES + GENERATED_BUILD_FILES:
        blobs[rel] = (REAL_ROOT / rel).read_bytes()
    for rel in COPIED_DIRS:
        for path in sorted((REAL_ROOT / rel).rglob("*")):
            if path.is_file():
                blobs[path.relative_to(REAL_ROOT).as_posix()] = path.read_bytes()
    # Real bodies, not empty placeholders: NONNEG_ENFORCEMENT_EMPTY and
    # NONNEG_ENFORCEMENT_UNNAMED can only be exercised against real content.
    for module in sorted((REAL_ROOT / "tools" / "tests").glob("*.py")):
        blobs[f"tools/tests/{module.name}"] = module.read_bytes()
    return blobs


_SNAPSHOT = _snapshot()
_MODULE_PATHS = tuple(
    m["path"] for m in json.loads(
        (REAL_ROOT / "governance" / "module-registry.json").read_text("utf-8"))["modules"])
_SIMULATOR_PATHS = tuple(
    s["build_context"] for s in json.loads(
        (REAL_ROOT / "governance" / "dev-platform.json").read_text("utf-8"))["simulators"])



def _scratch_dir() -> str | None:
    """Prefer a RAM-backed scratch directory for fixture materialisation.

    Every test builds a fresh repository of ~250 files, and the default temp
    directory sits on the same slow mount as the repository itself. Writing the
    fixtures to tmpfs cuts the suite's wall-clock several-fold and changes
    nothing about what is tested: the fixture is still a real directory tree on
    a real filesystem. Falls back to the default when /dev/shm is unavailable or
    too small.
    """
    shm = Path("/dev/shm")
    try:
        if shm.is_dir() and os.access(shm, os.W_OK):
            usage = shutil.disk_usage(shm)
            if usage.free > 256 * 1024 * 1024:
                return str(shm)
    except OSError:
        pass
    return None


_SCRATCH = _scratch_dir()


def _stat_pair(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return (stat.st_size, stat.st_mtime_ns)


class FixtureRepo:
    """A temporary repository root that satisfies ``repo_root`` discovery.

    Every mutation goes through :meth:`write`, :meth:`mutate` or :meth:`remove`
    so the fixture knows exactly which paths a test touched. That is what makes
    :meth:`restore` cheap, and :meth:`restore` is what lets one fixture serve a
    whole process instead of being rebuilt ~1500 times: profiling at B33 showed
    78% of the suite's wall clock was fixture creation and deletion, and the
    suite had reached the ceiling on a single execution step.

    Tests must not write through ``fixture.root`` directly. If they do, the
    change is invisible to :meth:`restore` and leaks into the next test — set
    ``PAYGOV_FIXTURE_FRESH=1`` to build a fresh fixture per test and confirm a
    suspected leak is real.
    """

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="paygov-fixture-", dir=_SCRATCH)
        self.root = Path(self._tmp.name)
        self._dirty: set[str] = set()
        (self.root / "tools" / "paygov").mkdir(parents=True)
        (self.root / "tools" / "tests").mkdir(parents=True)
        for rel, blob in _SNAPSHOT.items():
            dst = self.root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(blob)
        # Mirror declared module directories so MODULE_PATH checks pass.
        for path in _MODULE_PATHS + _SIMULATOR_PATHS:
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self._marks = self._baseline()

    def read(self, rel: str):
        return json.loads((self.root / rel).read_text(encoding="utf-8"))

    def write(self, rel: str, data, encoding: str = "utf-8") -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        self._dirty.add(rel)
        if isinstance(data, (dict, list)):
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                            encoding=encoding)
        elif isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(str(data), encoding=encoding)

    def mutate(self, rel: str, fn) -> None:
        data = self.read(rel)
        fn(data)
        self.write(rel, data)

    def remove(self, rel: str, missing_ok: bool = False) -> None:
        """Delete a file and remember it, so ``restore`` can put it back."""
        self._dirty.add(rel)
        (self.root / rel).unlink(missing_ok=missing_ok)

    def _baseline(self) -> dict[str, tuple[int, int]]:
        marks: dict[str, tuple[int, int]] = {}
        for rel in _SNAPSHOT:
            try:
                stat = (self.root / rel).stat()
            except OSError:
                continue
            marks[rel] = (stat.st_size, stat.st_mtime_ns)
        return marks

    def restore(self) -> None:
        """Return the fixture to pristine, whatever the test did to it.

        Deliberately a diff against the snapshot rather than an undo log: tests
        mutate fixtures in half a dozen styles (``write``, ``remove``, a raw
        ``Path.write_text`` on a path they built themselves, a rename), and an
        undo log silently misses the styles it does not know about — which
        leaks state into the next test and is exactly the class of bug that
        makes a shared fixture dangerous. Walking ~250 files costs a couple of
        milliseconds against the ~14 ms a rebuild costs.
        """
        seen: set[str] = set()
        for directory, _, names in os.walk(self.root):
            base = Path(directory)
            for name in names:
                path = base / name
                rel = path.relative_to(self.root).as_posix()
                seen.add(rel)
                blob = _SNAPSHOT.get(rel)
                if blob is None:
                    path.unlink()
                    continue
                stat = path.stat()
                if (stat.st_size, stat.st_mtime_ns) != self._marks.get(rel):
                    path.write_bytes(blob)
                    self._marks[rel] = _stat_pair(path)
        for rel, blob in _SNAPSHOT.items():
            if rel in seen:
                continue
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            self._marks[rel] = _stat_pair(path)
        self._dirty.clear()

    def close(self) -> None:
        self._tmp.cleanup()


_SHARED: FixtureRepo | None = None


def _shared_fixture() -> FixtureRepo:
    """One fixture per process, restored between tests."""
    global _SHARED
    if _SHARED is None:
        _SHARED = FixtureRepo()
    return _SHARED


class FixtureTestCase(unittest.TestCase):
    """Base class giving each test an isolated fixture repository."""

    #: Set on a test case that genuinely needs a private fixture directory.
    FRESH_FIXTURE = False

    def setUp(self) -> None:
        # Catalogue lookups are cached per repository root; fixtures rewrite
        # those files, so the cache must be dropped around every test.
        catalogue.reset_cache()
        self.addCleanup(catalogue.reset_cache)
        if self.FRESH_FIXTURE or os.environ.get("PAYGOV_FIXTURE_FRESH"):
            self.fixture = FixtureRepo()
            self.addCleanup(self.fixture.close)
        else:
            self.fixture = _shared_fixture()
            self.addCleanup(self.fixture.restore)

    def new_fixture(self) -> FixtureRepo:
        """An extra isolated fixture, for tests that need several at once."""
        fixture = FixtureRepo()
        self.addCleanup(fixture.close)
        return fixture

    def write_synthetic_evidence(self, fixture: "FixtureRepo", batch: str = "B00",
                                 *, controls=None, tests=None, passed: int = 3) -> None:
        """Create a minimal, internally consistent evidence tree inside a fixture."""
        base = fixture.root / "evidence" / batch
        for name in ("test-results", "runtime", "security"):
            (base / name).mkdir(parents=True, exist_ok=True)
            (base / name / "result.log").write_text("ok\n", encoding="utf-8")
        (base / "plan.md").write_text(
            "# plan\n\n" + "\n".join(f"## {i}. {s}" for i, s in enumerate(
                ["范围", "受影响组件", "领域接口与数据契约", "错误语义", "命令", "测试策略",
                 "回滚", "威胁变化", "数据迁移", "证据与审查"], 1)) + "\n" + "detail. " * 40,
            encoding="utf-8")
        (base / "commands.spec.json").write_text(json.dumps({"batch": batch, "commands": [
            {"purpose": "env", "expect": 0, "command": "python3 -VV"},
            {"purpose": "summary", "expect": 0,
             "command": (f"python3 scripts/test-summary.py "
                         f"--out evidence/{batch}/test-results/summary.json "
                         f"--log evidence/{batch}/test-results/unittest.log")},
            {"purpose": "gate", "expect": 0, "command": "python3 -m tools.paygov.cli verify-all"},
            {"purpose": "negative", "expect": 0, "command": "python3 scripts/negative-controls.py"},
            {"purpose": "timeout", "expect": 3, "command": "paygov verify x --budget-seconds 0"},
            {"purpose": "idempotency", "expect": 0, "command": "diff a b && echo IDENTICAL"},
        ]}), encoding="utf-8")
        (base / "commands.ndjson").write_text("\n".join(json.dumps(
            {"timestamp": "2026-08-18T00:00:00Z", "command": c["command"],
             "exit_code": c["expect"], "expected_exit_code": c["expect"]})
            for c in json.loads((base / "commands.spec.json").read_text("utf-8"))["commands"]
        ) + "\n", encoding="utf-8")
        (base / "test-results" / "summary.json").write_text(json.dumps(
            {"run": passed, "passed": passed, "failed": 0, "skipped": 0,
             "skipped_critical": 0, "shard": "1/1", "shards": 1}), encoding="utf-8")
        (base / "traceability.json").write_text(json.dumps({
            "batch_id": batch, "requirements": [{"id": "R1"}],
            "code": [{"ref": "governance/project-config.json"}],
            "tests": tests if tests is not None else [{"ref": "tools/tests/test_b00_cli.py"}],
            "controls": controls if controls is not None else [{"id": "NN-01"}],
            "evidence": [{"path": f"evidence/{batch}/plan.md"}]}), encoding="utf-8")
        artefact = "governance/project-config.json"
        (base / "artifacts.json").write_text(json.dumps([artefact]), encoding="utf-8")
        completion = fixture.root / "evidence" / "completion"
        completion.mkdir(parents=True, exist_ok=True)
        (completion / f"{batch}.json").write_text(json.dumps({
            "batch_id": batch, "status": "passed", "commit_sha": "a" * 40,
            "environment": "integration", "started_at": "2026-08-18T00:00:00Z",
            "completed_at": "2026-08-18T00:01:00Z", "executor": "claude-agent",
            "reviewer": "Ethan",
            "artifacts": [{"path": artefact, "sha256": "0" * 64}],
            "tests": {"passed": passed, "failed": 0, "skipped_critical": 0},
            "security": {"blocking_findings": 0, "accepted_findings": 0},
            "dependency_hashes": {}}), encoding="utf-8")

        # Register everything this helper created so a shared fixture can be
        # returned to pristine. The directories it makes are left in place;
        # only files carry state.
        for rel in (f"evidence/{batch}/plan.md",
                    f"evidence/{batch}/commands.spec.json",
                    f"evidence/{batch}/commands.ndjson",
                    f"evidence/{batch}/traceability.json",
                    f"evidence/{batch}/artifacts.json",
                    f"evidence/{batch}/test-results/summary.json",
                    f"evidence/{batch}/test-results/result.log",
                    f"evidence/{batch}/runtime/result.log",
                    f"evidence/{batch}/security/result.log",
                    f"evidence/completion/{batch}.json"):
            fixture._dirty.add(rel)

    def codes(self, problems) -> set[str]:
        return {p.code for p in problems}

    def rules(self, problems) -> set[str]:
        return {p.rule for p in problems}
