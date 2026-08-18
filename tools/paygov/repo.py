"""Repository access with explicit byte and wall-clock budgets.

Governance validators run inside CI and inside the batch evidence gate. A
malformed or hostile file must not be able to hang the gate: every read is
bounded, and exceeding a bound raises :class:`BudgetExceeded` which the CLI
converts into a *failure*, never into a pass. This is the fail-closed rule
(NN-12) applied to the toolchain itself.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, GovernanceError

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_SECONDS = 30.0

# Directories that are vendored inputs or build output: they are read-only for
# governance purposes and must never be scanned or rewritten by paygov.
EXCLUDED_DIR_NAMES = frozenset({
    ".git", "__pycache__", "node_modules", ".gradle", "build", "out",
    "target", "dist", ".venv", ".idea", ".vscode",
})
EXCLUDED_TOP_LEVEL = (
    ".payment-platform",
    ".claude",
    ".agents",
    "enterprise-payment-platform-skills-v1.0.0",
)


@dataclass
class Budget:
    """A shared wall-clock budget for one validator run."""

    seconds: float = DEFAULT_SECONDS
    max_bytes: int = DEFAULT_MAX_BYTES
    _started: float | None = None

    def start(self) -> "Budget":
        self._started = time.monotonic()
        return self

    def elapsed(self) -> float:
        if self._started is None:
            return 0.0
        return time.monotonic() - self._started

    def check(self, where: str = "") -> None:
        if self._started is None:
            return
        if self.elapsed() > self.seconds:
            raise BudgetExceeded(
                f"governance budget of {self.seconds}s exceeded while reading {where or '<repo>'}"
            )


def repo_root(start: Path | str | None = None) -> Path:
    """Locate the repository root by walking up to the marker directory."""
    here = Path(start) if start else Path(__file__).resolve()
    here = here if here.is_dir() else here.parent
    for candidate in [here, *here.parents]:
        if (candidate / "governance").is_dir() and (candidate / "tools" / "paygov").is_dir():
            return candidate
    raise GovernanceError(f"repository root not found from {here}")


def read_text(path: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    budget.check(str(path))
    if not path.is_file():
        raise GovernanceError(f"required file is missing: {path}")
    size = path.stat().st_size
    if size > budget.max_bytes:
        raise BudgetExceeded(f"{path} is {size} bytes, above the {budget.max_bytes} byte budget")
    return path.read_text(encoding="utf-8")


def load_json(path: Path, budget: Budget | None = None) -> Any:
    raw = read_text(path, budget)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GovernanceError(f"{path} is not valid JSON: {exc}") from exc


def iter_repo_files(root: Path, budget: Budget | None = None, *, suffixes: tuple[str, ...] | None = None):
    """Yield every first-party file, skipping vendored and generated trees."""
    budget = budget or Budget().start()
    excluded_roots = {(root / name).resolve() for name in EXCLUDED_TOP_LEVEL}
    stack = [root]
    while stack:
        current = stack.pop()
        budget.check(str(current))
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in sorted(entries):
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in EXCLUDED_DIR_NAMES or entry.resolve() in excluded_roots:
                    continue
                stack.append(entry)
            elif entry.is_file():
                if suffixes and entry.suffix not in suffixes:
                    continue
                yield entry
