"""B00 — non-negotiable registry validation.

``governance/non-negotiables.json`` is the machine-readable mirror of
``policies/non-negotiables.md``. Drift between the two is itself a finding: a
red line that exists only in prose cannot be enforced by CI.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import Problem
from .repo import Budget, load_json, read_text
from .structs import BATCH_ID, SEMVER, expect

REGISTRY_PATH = Path("governance/non-negotiables.json")
POLICY_PATH = Path(".payment-platform/skill-package/policies/non-negotiables.md")
TESTS_DIR = Path("tools/tests")

EXPECTED_RULE_COUNT = 15
VALID_SEVERITY = {"critical", "high", "medium"}
VALID_STATUS = {"active", "planned"}
POLICY_ITEM = re.compile(r"^\d+\.\s+\*\*(.+?)\*\*", re.MULTILINE)


def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(REGISTRY_PATH)
    try:
        registry: Any = load_json(root / REGISTRY_PATH, budget)
    except Exception as exc:
        return [Problem("NONNEG_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(registry.get("schema_version", "")))),
                       "NONNEG_VERSION", where, "schema_version must be semantic version", "NN-12")

    rules = registry.get("rules")
    if not isinstance(rules, list):
        return problems + [Problem("NONNEG_SHAPE", where, "rules must be an array", "NN-12")]

    problems += expect(len(rules) == EXPECTED_RULE_COUNT, "NONNEG_COUNT", where,
                       f"expected {EXPECTED_RULE_COUNT} non-negotiables, found {len(rules)}", "NN-12",
                       found=len(rules))

    seen: set[str] = set()
    for index, rule in enumerate(rules):
        scope = f"{where}#rules[{index}]"
        if not isinstance(rule, dict):
            problems.append(Problem("NONNEG_SHAPE", scope, "rule must be an object", "NN-12"))
            continue
        rid = rule.get("id", "")
        expected_id = f"NN-{index + 1:02d}"
        problems += expect(rid == expected_id, "NONNEG_ID", scope,
                           f"rule ids must be dense and ordered; expected {expected_id}, got '{rid}'",
                           "NN-12")
        problems += expect(rid not in seen, "NONNEG_ID", scope, f"duplicate rule id '{rid}'", "NN-12")
        seen.add(rid)
        problems += expect(bool(str(rule.get("title", "")).strip()), "NONNEG_TITLE", scope,
                           "rule must have a title", "NN-12")
        problems += expect(rule.get("severity") in VALID_SEVERITY, "NONNEG_SEVERITY", scope,
                           f"severity must be one of {sorted(VALID_SEVERITY)}", "NN-12")
        problems += expect(rule.get("status") in VALID_STATUS, "NONNEG_STATUS", scope,
                           f"status must be one of {sorted(VALID_STATUS)}", "NN-12")
        problems += _enforcement(root, rule, scope, rid)

    problems += _policy_parity(root, rules, where, budget)
    return problems


def _enforcement(root: Path, rule: dict, scope: str, rid: str) -> list[Problem]:
    enforced = rule.get("enforced_by")
    if not isinstance(enforced, list) or not enforced:
        return [Problem("NONNEG_ENFORCEMENT", scope,
                        "every non-negotiable needs at least one enforcement reference", rid)]
    problems: list[Problem] = []
    has_test = False
    for ref in enforced:
        if not isinstance(ref, str) or ":" not in ref:
            problems.append(Problem("NONNEG_ENFORCEMENT", scope,
                                    f"malformed enforcement reference '{ref}'", rid))
            continue
        kind, value = ref.split(":", 1)
        if kind == "test":
            has_test = True
            module = root / TESTS_DIR / f"{value}.py"
            if not module.is_file():
                problems.append(Problem("NONNEG_ENFORCEMENT", scope,
                                        f"enforcement test module '{value}' does not exist", rid))
        elif kind == "batch":
            if not BATCH_ID.match(value):
                problems.append(Problem("NONNEG_ENFORCEMENT", scope,
                                        f"'{value}' is not a valid batch id", rid))
        else:
            problems.append(Problem("NONNEG_ENFORCEMENT", scope,
                                    f"unknown enforcement kind '{kind}'", rid))
    if rule.get("status") == "active" and not has_test:
        problems.append(Problem("NONNEG_ACTIVE_WITHOUT_TEST", scope,
                                "a rule marked 'active' must be enforced by at least one existing test; "
                                "otherwise mark it 'planned' with the owning batch", rid))
    return problems


def _policy_parity(root: Path, rules: list, where: str, budget: Budget) -> list[Problem]:
    """The registry must have exactly one entry per numbered policy statement."""
    policy = root / POLICY_PATH
    if not policy.is_file():
        return [Problem("NONNEG_POLICY_MISSING", str(POLICY_PATH),
                        "upstream policy document is missing; cannot prove parity", "NN-12")]
    text = read_text(policy, budget)
    policy_items = POLICY_ITEM.findall(text)
    return expect(len(policy_items) == len(rules), "NONNEG_PARITY", where,
                  f"registry has {len(rules)} rules but the upstream policy defines "
                  f"{len(policy_items)} statements", "NN-12",
                  policy_items=len(policy_items), registry_rules=len(rules))
