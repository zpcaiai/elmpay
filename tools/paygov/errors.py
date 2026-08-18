"""Problem reporting primitives shared by every governance validator."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


class GovernanceError(Exception):
    """Raised for unrecoverable validator input problems (fail closed)."""


class BudgetExceeded(GovernanceError):
    """Raised when a validator exceeds its wall-clock or byte budget."""


@dataclass(frozen=True)
class Problem:
    """A single, machine-readable governance violation.

    ``code`` is stable and greppable; ``rule`` links the finding back to a
    non-negotiable (``NN-xx``) or control (``CTRL-xxx``) so that CI output can
    be traced to policy without human interpretation.
    """

    code: str
    where: str
    message: str
    rule: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:  # pragma: no cover - convenience only
        prefix = f"[{self.code}]"
        rule = f" ({self.rule})" if self.rule else ""
        return f"{prefix}{rule} {self.where}: {self.message}"


def render(problems: Iterable[Problem], *, indent: int = 2) -> str:
    """Deterministic JSON rendering so repeated runs are byte-identical."""
    ordered = sorted(problems, key=lambda p: (p.code, p.where, p.message))
    return json.dumps(
        {"ok": not ordered, "problem_count": len(ordered),
         "problems": [p.as_dict() for p in ordered]},
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
    )
