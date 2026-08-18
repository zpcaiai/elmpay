"""Fixture helpers: build a disposable copy of the governance surface.

Negative tests must be able to corrupt configuration without touching the real
repository, so every mutation test runs against a temporary clone that contains
only the files the validators read.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.paygov import catalogue
from tools.paygov.repo import repo_root

REAL_ROOT = repo_root(Path(__file__).resolve())

COPIED_FILES = (
    "governance/project-config.json",
    "governance/non-negotiables.json",
    "governance/module-registry.json",
    "governance/requirements.json",
    "governance/service-boundaries.json",
    "governance/threat-model.json",
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

COPIED_DIRS = (
    "docs/adr",
    "docs/security",
)


def _snapshot() -> dict[str, bytes]:
    """Read every fixture input once.

    The repository lives on a slow mount and the suite builds a fresh fixture
    per test; reading the sources once and writing from memory keeps the suite
    fast without weakening isolation.
    """
    blobs: dict[str, bytes] = {}
    for rel in COPIED_FILES:
        blobs[rel] = (REAL_ROOT / rel).read_bytes()
    for rel in COPIED_DIRS:
        for path in sorted((REAL_ROOT / rel).rglob("*")):
            if path.is_file():
                blobs[path.relative_to(REAL_ROOT).as_posix()] = path.read_bytes()
    for module in sorted((REAL_ROOT / "tools" / "tests").glob("test_*.py")):
        blobs[f"tools/tests/{module.name}"] = b""
    return blobs


_SNAPSHOT = _snapshot()
_MODULE_PATHS = tuple(
    m["path"] for m in json.loads(
        (REAL_ROOT / "governance" / "module-registry.json").read_text("utf-8"))["modules"])


class FixtureRepo:
    """A temporary repository root that satisfies ``repo_root`` discovery."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="paygov-fixture-")
        self.root = Path(self._tmp.name)
        (self.root / "tools" / "paygov").mkdir(parents=True)
        (self.root / "tools" / "tests").mkdir(parents=True)
        for rel, blob in _SNAPSHOT.items():
            dst = self.root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(blob)
        # Mirror declared module directories so MODULE_PATH checks pass.
        for path in _MODULE_PATHS:
            (self.root / path).mkdir(parents=True, exist_ok=True)

    def read(self, rel: str):
        return json.loads((self.root / rel).read_text(encoding="utf-8"))

    def write(self, rel: str, data) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, (dict, list)):
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            path.write_text(str(data), encoding="utf-8")

    def mutate(self, rel: str, fn) -> None:
        data = self.read(rel)
        fn(data)
        self.write(rel, data)

    def close(self) -> None:
        self._tmp.cleanup()


class FixtureTestCase(unittest.TestCase):
    """Base class giving each test an isolated fixture repository."""

    def setUp(self) -> None:
        # Catalogue lookups are cached per repository root; fixtures rewrite
        # those files, so the cache must be dropped around every test.
        catalogue.reset_cache()
        self.addCleanup(catalogue.reset_cache)
        self.fixture = FixtureRepo()
        self.addCleanup(self.fixture.close)

    def codes(self, problems) -> set[str]:
        return {p.code for p in problems}

    def rules(self, problems) -> set[str]:
        return {p.rule for p in problems}
