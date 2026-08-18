"""Fixture helpers: build a disposable copy of the governance surface.

Negative tests must be able to corrupt configuration without touching the real
repository, so every mutation test runs against a temporary clone that contains
only the files the validators read.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.paygov.repo import repo_root

REAL_ROOT = repo_root(Path(__file__).resolve())

COPIED_FILES = (
    "governance/project-config.json",
    "governance/non-negotiables.json",
    "governance/module-registry.json",
    "docs/charter/PROGRAM_CHARTER.md",
    "docs/charter/RISK_ACCEPTANCE_POLICY.md",
    "docs/charter/DELIVERY_MODEL.md",
    ".payment-platform/skill-package/policies/non-negotiables.md",
)


class FixtureRepo:
    """A temporary repository root that satisfies ``repo_root`` discovery."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="paygov-fixture-")
        self.root = Path(self._tmp.name)
        (self.root / "tools" / "paygov").mkdir(parents=True)
        (self.root / "tools" / "tests").mkdir(parents=True)
        for rel in COPIED_FILES:
            src = REAL_ROOT / rel
            dst = self.root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        # Mirror the test module names so non-negotiable enforcement references resolve.
        for module in sorted((REAL_ROOT / "tools" / "tests").glob("test_*.py")):
            (self.root / "tools" / "tests" / module.name).write_text("", encoding="utf-8")
        # Mirror declared module directories so MODULE_PATH checks pass.
        registry = json.loads((self.root / "governance" / "module-registry.json").read_text("utf-8"))
        for module in registry["modules"]:
            (self.root / module["path"]).mkdir(parents=True, exist_ok=True)

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
        self.fixture = FixtureRepo()
        self.addCleanup(self.fixture.close)

    def codes(self, problems) -> set[str]:
        return {p.code for p in problems}

    def rules(self, problems) -> set[str]:
        return {p.rule for p in problems}
