"""B01 — requirement baseline validation.

A requirement is only "baselined" when it is uniquely identified, owned by a
module that exists, bound to at least one control, and verifiable by at least
one batch that exists in the programme manifest. Anything less is a wish, and
the traceability matrix built in B07 would silently inherit the gap.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import catalogue
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import BATCH_ID, SEMVER, expect

PATH = Path("governance/requirements.json")
REQ_ID = "PAY-REQ-{:04d}"
VALID_PRIORITY = {"MUST", "SHOULD"}
VALID_STATUS = {"baselined", "deferred"}
# Minimum lengths are counted in characters, tuned for CJK prose: a four
# character title is already a full noun phrase, whereas a statement or an
# acceptance criterion that short cannot be testable.
MIN_TEXT = {"title": 4, "statement": 16, "acceptance": 12}


def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("REQ_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "REQ_VERSION", where, "schema_version must be semantic version", "NN-12")

    categories = doc.get("categories")
    requirements = doc.get("requirements")
    if not isinstance(categories, list) or not isinstance(requirements, list) or not requirements:
        return problems + [Problem("REQ_SHAPE", where,
                                   "requirements.json needs 'categories' and a non-empty "
                                   "'requirements' array", "NN-12")]

    known_batches = catalogue.batch_ids(str(root))
    known_controls = catalogue.control_ids(str(root))
    known_modules = catalogue.module_names(str(root))
    known_rules = catalogue.non_negotiable_ids(str(root))

    seen: set[str] = set()
    owners: set[str] = set()
    used_categories: set[str] = set()

    for index, req in enumerate(requirements, 1):
        scope = f"{where}#requirements[{index - 1}]"
        if not isinstance(req, dict):
            problems.append(Problem("REQ_SHAPE", scope, "requirement must be an object", "NN-12"))
            continue
        rid = req.get("id", "")
        scope = f"{where}#{rid or index}"
        problems += expect(rid == REQ_ID.format(index), "REQ_ID", scope,
                           f"requirement ids must be dense and ordered; expected "
                           f"{REQ_ID.format(index)}, got '{rid}'", "NN-12")
        problems += expect(rid not in seen, "REQ_ID", scope, f"duplicate requirement id '{rid}'",
                           "NN-12")
        seen.add(rid)

        for field, minimum in MIN_TEXT.items():
            value = str(req.get(field, "")).strip()
            problems += expect(len(value) >= minimum, "REQ_TEXT", scope,
                               f"'{field}' must be at least {minimum} characters to be reviewable",
                               "NN-12")

        category = req.get("category")
        used_categories.add(category)
        problems += expect(category in categories, "REQ_CATEGORY", scope,
                           f"unknown category '{category}'", "NN-12")
        problems += expect(req.get("priority") in VALID_PRIORITY, "REQ_PRIORITY", scope,
                           f"priority must be one of {sorted(VALID_PRIORITY)}", "NN-12")
        problems += expect(req.get("status") in VALID_STATUS, "REQ_STATUS", scope,
                           f"status must be one of {sorted(VALID_STATUS)}", "NN-12")

        owner = req.get("owner_module")
        owners.add(owner)
        problems += expect(owner in known_modules, "REQ_OWNER", scope,
                           f"owner_module '{owner}' is not in the module registry", "NN-12")

        controls = req.get("controls")
        problems += expect(isinstance(controls, list) and bool(controls), "REQ_CONTROL", scope,
                           "every requirement must reference at least one control", "NN-12")
        if isinstance(controls, list):
            for control in controls:
                ok = control in known_rules or control in known_controls
                problems += expect(ok, "REQ_CONTROL", scope,
                                   f"control '{control}' exists neither in the non-negotiable "
                                   f"registry nor in the control matrix", "NN-12")

        batches = req.get("verified_by_batches")
        problems += expect(isinstance(batches, list) and bool(batches), "REQ_VERIFICATION", scope,
                           "every requirement must name at least one verifying batch", "NN-12")
        if isinstance(batches, list):
            for batch in batches:
                ok = isinstance(batch, str) and bool(BATCH_ID.match(batch)) and batch in known_batches
                problems += expect(ok, "REQ_VERIFICATION", scope,
                                   f"'{batch}' is not a batch defined by the programme manifest",
                                   "NN-12")

    for category in categories:
        problems += expect(category in used_categories, "REQ_CATEGORY", where,
                           f"category '{category}' is declared but unused", "NN-12")

    for module in sorted(known_modules - owners):
        problems.append(Problem("REQ_MODULE_UNCOVERED", where,
                                f"module '{module}' owns no requirement; either give it one or "
                                f"remove it from the module registry", "NN-12"))
    return problems
