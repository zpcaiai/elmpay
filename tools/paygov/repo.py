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
# CPU seconds, not wall-clock seconds. See ADR-0015.
DEFAULT_SECONDS = 30.0
# A validator that is not spending CPU is not working, it is stuck. The ceiling
# exists to catch that — a stalled mount, a hostile FIFO — and nothing else, so
# it is deliberately far above any honest run.
WALL_CEILING_MULTIPLIER = 10.0

# Directories that are vendored inputs or build output: they are read-only for
# governance purposes and must never be scanned or rewritten by paygov.
EXCLUDED_DIR_NAMES = frozenset({
    ".git", "__pycache__", "node_modules", ".gradle", "build", "out",
    "target", "dist", ".venv", ".idea", ".vscode",
})
# Matched against top-level names only. "enterprise-payment-platform-skills-v1.0.0"
# used to be listed here and was removed: that directory lives at
# skills/enterprise-payment-platform-skills-v1.0.0, so the entry had never matched
# anything since the copy moved. An exclusion that matches nothing is not a
# harmless leftover — it reads as protection in a diff and behaves as absence, and
# the module docstring above was describing it as though it worked. The vendored
# copy under skills/ is therefore scanned like any other tree, which is the safe
# direction to be wrong in; its integrity is separately pinned by CHECKSUMS.sha256
# and `make skills-verify`.
EXCLUDED_TOP_LEVEL = (
    ".payment-platform",
    ".claude",
    ".agents",
)


@dataclass
class Budget:
    """A CPU-time budget for one validator run, with a wall-clock backstop.

    This used to be wall-clock only, and that made the verdict a property of the
    machine rather than of the repository. Measured on 2026-09-01: ``repo-hygiene``
    spent **5.9 CPU-seconds** and **23.3 wall-seconds** — 25% CPU, the rest of it
    waiting on file reads. Against a 30-second wall budget that is a gate running
    at 78% of its limit while doing six seconds of work, and it aborted twice, both
    times just after a heavy Gradle build had given the machine something else to
    do. A gate that cannot finish is not judging; ``VALIDATOR_ABORTED`` is exit 3,
    and exit 3 is indistinguishable from "the tool is broken, skip it".

    So the budget now counts the work, and a separate, generous ceiling counts the
    waiting. Exceeding either still fails closed — the ceiling is what still catches
    a validator wedged on a stalled mount, which CPU time alone never would.
    """

    seconds: float = DEFAULT_SECONDS
    max_bytes: int = DEFAULT_MAX_BYTES
    wall_ceiling: float | None = None
    _started: float | None = None
    _cpu_started: float | None = None

    def start(self) -> "Budget":
        self._started = time.monotonic()
        self._cpu_started = time.process_time()
        return self

    def elapsed(self) -> float:
        if self._started is None:
            return 0.0
        return time.monotonic() - self._started

    def cpu_elapsed(self) -> float:
        if self._cpu_started is None:
            return 0.0
        return time.process_time() - self._cpu_started

    def ceiling(self) -> float:
        if self.wall_ceiling is not None:
            return self.wall_ceiling
        return self.seconds * WALL_CEILING_MULTIPLIER

    def check(self, where: str = "") -> None:
        if self._started is None:
            return
        if self.cpu_elapsed() > self.seconds:
            raise BudgetExceeded(
                f"governance budget of {self.seconds}s CPU exceeded while reading "
                f"{where or '<repo>'}"
            )
        if self.elapsed() > self.ceiling():
            raise BudgetExceeded(
                f"governance wall-clock ceiling of {self.ceiling()}s exceeded while reading "
                f"{where or '<repo>'} after only {self.cpu_elapsed():.1f}s of CPU: a validator "
                f"that is not spending CPU is stuck, not working"
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
