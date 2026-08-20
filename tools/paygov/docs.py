"""B01/B07 — generated-document drift gate.

If a reviewer reads a document that no longer matches the JSON the gate
enforces, the review is worthless. Drift is therefore a build failure.
"""
from __future__ import annotations

from pathlib import Path

from .errors import Problem
from .render import render_all
from .repo import Budget


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("generated-docs", "B01")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    problems: list[Problem] = []
    for rel, expected in sorted(render_all(root).items()):
        budget.check(rel)
        path = root / rel
        if not path.is_file():
            problems.append(Problem("DOC_MISSING", rel,
                                    "generated document is missing; run scripts/render-docs.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("DOC_DRIFT", rel,
                                    "generated document differs from its source of truth; "
                                    "run scripts/render-docs.py", "NN-12"))
    return problems
