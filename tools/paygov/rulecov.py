"""Rule-coverage gate.

A validator rule that no test and no negative control can trigger is
indistinguishable from a rule that does not exist: it can be deleted without
anything going red. An independent review of Wave W00 removed four real
security rules from source and the whole suite still passed, which is exactly
this failure mode.

This validator extracts every ``Problem`` code emitted by ``tools/paygov`` and
requires each one to be referenced by a test module or by a runtime negative
control. Codes that are genuinely unreachable must be deleted, not exempted.
"""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from .errors import Problem
from .repo import Budget

PACKAGE = Path("tools/paygov")
TESTS = Path("tools/tests")
NEGATIVE_CONTROLS = Path("scripts/negative-controls.py")
# Scenarios moved out of the runner script into one module per batch; the
# coverage corpus has to follow them or every new rule would read as uncovered.
NEGATIVE_SCENARIOS = Path("tools/negative")
CODE_LITERAL = re.compile(r"^[A-Z][A-Z0-9_]{3,}$")


# Identity-keyed memo over the validator package. Parsing ~60 modules with the
# AST is the single most expensive thing the gate does, two validators want the
# answer, and the negative-control harness asks 240 times for a package that
# never changes between scenarios. Keyed on (path, size, mtime_ns): same bytes,
# same answer.
_EMITTED_CACHE: dict[tuple, dict[str, list[str]]] = {}
_EMITTED_LIMIT = 16


def _package_stamp(root: Path) -> tuple:
    stamp = []
    for path in sorted((root / PACKAGE).glob("*.py")):
        try:
            stat = path.stat()
        except OSError:
            continue
        stamp.append((path.name, stat.st_size, stat.st_mtime_ns))
    return tuple(stamp)


def emitted_codes(root: Path, budget: Budget | None = None) -> dict[str, list[str]]:
    """Map every Problem code emitted by the package to the sites that emit it."""
    budget = budget or Budget().start()
    stamp = _package_stamp(root)
    cached = _EMITTED_CACHE.get(stamp)
    if cached is not None:
        return {code: list(sites) for code, sites in cached.items()}
    found: dict[str, list[str]] = {}
    for path in sorted((root / PACKAGE).glob("*.py")):
        budget.check(str(path))
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else "")
            code: str | None = None
            if name == "Problem" and node.args and isinstance(node.args[0], ast.Constant):
                code = node.args[0].value
            elif name == "expect" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                # expect(condition, code, where, message, rule)
                code = node.args[1].value
            else:
                for keyword in node.keywords:
                    if keyword.arg == "code" and isinstance(keyword.value, ast.Constant):
                        code = keyword.value.value
            if isinstance(code, str) and CODE_LITERAL.match(code):
                found.setdefault(code, []).append(f"{rel}:{node.lineno}")
    if len(_EMITTED_CACHE) >= _EMITTED_LIMIT:
        _EMITTED_CACHE.clear()
    _EMITTED_CACHE[stamp] = {code: list(sites) for code, sites in found.items()}
    return found


# Content-keyed memo, same reasoning as tools/paygov/hygiene.py: tokenising
# ~1.5MB of tests is pure work over bytes, and the negative-control harness runs
# the gate 180+ times over trees where the test corpus never changes at all.
_TOKEN_CACHE: dict[str, set[str]] = {}
_CACHE_LIMIT = 4096


def _tokens(text: str) -> set[str]:
    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    hit = _TOKEN_CACHE.get(key)
    if hit is None:
        hit = {token for token in re.findall(r"[A-Z][A-Z0-9_]{3,}", text)}
        if len(_TOKEN_CACHE) >= _CACHE_LIMIT:
            _TOKEN_CACHE.clear()
        _TOKEN_CACHE[key] = hit
    return hit


def exercised_codes(root: Path, budget: Budget | None = None) -> set[str]:
    budget = budget or Budget().start()
    found: set[str] = set()
    sources = sorted((root / TESTS).glob("*.py")) + \
        sorted((root / NEGATIVE_SCENARIOS).glob("*.py"))
    controls = root / NEGATIVE_CONTROLS
    if controls.is_file():
        sources.append(controls)
    for path in sources:
        budget.check(str(path))
        found |= _tokens(path.read_text(encoding="utf-8"))
    return found


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("rule-coverage", "B07")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget(seconds=60).start()
    emitted = emitted_codes(root, budget)
    exercised = exercised_codes(root, budget)
    problems: list[Problem] = []
    for code in sorted(set(emitted) - exercised):
        problems.append(Problem("RULE_UNCOVERED", emitted[code][0],
                                f"rule code '{code}' is emitted by a validator but is not "
                                f"referenced by any test or negative control; a rule nothing can "
                                f"trigger can be deleted without anything going red", "NN-12",
                                {"emitted_at": emitted[code]}))
    return problems
