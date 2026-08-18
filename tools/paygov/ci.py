"""B05 — continuous integration and quality baseline gate.

The pipeline is only a control if it cannot be softened quietly. This validator
enforces that:

* every required stage exists, is marked ``required`` and ``fail_closed``;
* the stage graph is acyclic and every ``needs`` reference resolves;
* every GitHub Action is pinned to a 40-character commit SHA, never a tag;
* the workflow requests least-privilege permissions and never uses
  ``pull_request_target`` or ``continue-on-error`` on a required stage;
* the blocking conditions demanded by the batch document — severe security
  finding, ledger imbalance, unrecoverable state, missing evidence — are each
  declared and attached to a stage that can actually detect them;
* the generated workflow matches the declaration.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import cigen
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

PATH = Path("governance/ci-pipeline.json")
WORKFLOW = Path(".github/workflows/ci.yml")
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
RELEASE_GATES = {"RG0", "RG1", "RG2", "RG3", "RG4", "RG5", "RG6", "RG7"}
FORBIDDEN_IN_WORKFLOW = ("pull_request_target", "continue-on-error: true",
                         "permissions: write-all", "${{ secrets.")
REQUIRED_BLOCKING_TOPICS = {
    "BLOCK-01": "security",
    "BLOCK-02": "ledger",
    "BLOCK-03": "recovery",
    "BLOCK-04": "evidence",
}
MAX_ZERO_GATES = ("unit_test_failed_max", "skipped_critical_max",
                  "blocking_security_findings_max", "governance_problems_max")


def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("CI_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "CI_VERSION", where, "schema_version must be semantic version", "NN-12")

    stages = doc.get("stages")
    required = doc.get("required_stages")
    if not isinstance(stages, list) or not stages or not isinstance(required, list):
        return problems + [Problem("CI_SHAPE", where,
                                   "pipeline needs 'stages' and 'required_stages'", "NN-12")]

    by_id: dict[str, dict] = {}
    for stage in stages:
        sid = stage.get("id", "?")
        scope = f"{where}#{sid}"
        if sid in by_id:
            problems.append(Problem("CI_DUPLICATE", scope, f"duplicate stage '{sid}'", "NN-12"))
            continue
        by_id[sid] = stage
        problems += expect(bool(stage.get("commands")), "CI_STAGE", scope,
                           "a stage without commands does not check anything", "NN-12")
        problems += expect(stage.get("gate") in RELEASE_GATES, "CI_STAGE", scope,
                           f"gate must be one of {sorted(RELEASE_GATES)}", "NN-12")
        problems += expect(isinstance(stage.get("timeout_minutes"), int)
                           and 0 < stage["timeout_minutes"] <= 120, "CI_STAGE", scope,
                           "every stage needs a bounded timeout", "NN-12")
        if stage.get("required"):
            problems += expect(stage.get("fail_closed") is True, "CI_FAIL_OPEN", scope,
                               "a required stage must be fail-closed", "NN-12")

    for name in required:
        problems += expect(name in by_id, "CI_REQUIRED_STAGE", where,
                           f"required stage '{name}' is not defined", "NN-12")
        if name in by_id:
            problems += expect(by_id[name].get("required") is True, "CI_REQUIRED_STAGE", where,
                               f"stage '{name}' is listed as required but not marked required",
                               "NN-12")

    problems += _graph(by_id, where)
    problems += _actions(doc, where)
    problems += _permissions(doc, where)
    problems += _quality_gates(doc, where)
    problems += _blocking(doc, by_id, where)
    problems += _generated(root, budget)
    return problems


def _graph(by_id: dict[str, dict], where: str) -> list[Problem]:
    problems: list[Problem] = []
    for sid, stage in sorted(by_id.items()):
        for need in stage.get("needs", []):
            problems += expect(need in by_id, "CI_NEEDS", f"{where}#{sid}",
                               f"stage depends on unknown stage '{need}'", "NN-12")
    colour: dict[str, int] = {sid: 0 for sid in by_id}

    def visit(node: str, path: list[str]) -> None:
        colour[node] = 1
        for need in by_id[node].get("needs", []):
            if need not in by_id:
                continue
            if colour[need] == 1:
                problems.append(Problem("CI_CYCLE", f"{where}#{node}",
                                        "stage cycle: " + " -> ".join(path + [need]), "NN-12"))
            elif colour[need] == 0:
                visit(need, path + [need])
        colour[node] = 2

    for sid in sorted(by_id):
        if colour[sid] == 0:
            visit(sid, [sid])
    return problems


def _actions(doc: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    actions = doc.get("actions")
    if not isinstance(actions, list) or not actions:
        return [Problem("CI_ACTION", where, "'actions' must list every third-party action", "NN-12")]
    for action in actions:
        scope = f'{where}#{action.get("name", "?")}'
        problems += expect(bool(ACTION_SHA.match(str(action.get("ref", "")))), "CI_ACTION_PIN",
                           scope,
                           "third-party actions must be pinned to a full commit SHA, not a tag; "
                           "a tag can be moved to arbitrary code", "NN-12")
        problems += expect(len(str(action.get("version_comment", "")).strip()) >= 2,
                           "CI_ACTION", scope,
                           "record the human-readable version next to the pinned SHA", "NN-12")
    return problems


def _permissions(doc: dict, where: str) -> list[Problem]:
    permissions = doc.get("permissions")
    if not isinstance(permissions, dict) or not permissions:
        return [Problem("CI_PERMISSIONS", where, "'permissions' must be declared", "NN-12")]
    problems: list[Problem] = []
    problems += expect(permissions.get("contents") == "read", "CI_PERMISSIONS", where,
                       "the pipeline must not have write access to repository contents", "NN-11")
    for key, value in sorted(permissions.items()):
        problems += expect(value != "write-all", "CI_PERMISSIONS", where,
                           f"'{key}' must not be write-all", "NN-11")
    return problems


def _quality_gates(doc: dict, where: str) -> list[Problem]:
    gates = doc.get("quality_gates")
    if not isinstance(gates, dict):
        return [Problem("CI_QUALITY_GATE", where, "'quality_gates' must be declared", "NN-12")]
    problems: list[Problem] = []
    for key in MAX_ZERO_GATES:
        problems += expect(gates.get(key) == 0, "CI_QUALITY_GATE", where,
                           f"'{key}' must be 0; there is no 'passed with warnings' state", "NN-12")
    for key in ("line_coverage_min_percent", "mutation_score_min_percent"):
        value = gates.get(key)
        problems += expect(isinstance(value, int) and value > 0, "CI_QUALITY_GATE", where,
                           f"'{key}' must be a positive threshold", "NN-12")
    return problems


def _blocking(doc: dict, by_id: dict[str, dict], where: str) -> list[Problem]:
    conditions = doc.get("blocking_conditions")
    if not isinstance(conditions, list) or not conditions:
        return [Problem("CI_BLOCKING", where,
                        "'blocking_conditions' must declare what stops a release", "NN-12")]
    problems: list[Problem] = []
    seen: set[str] = set()
    for condition in conditions:
        cid = condition.get("id", "?")
        scope = f"{where}#{cid}"
        seen.add(cid)
        problems += expect(len(str(condition.get("description", "")).strip()) >= 6,
                           "CI_BLOCKING", scope, "blocking condition needs a description", "NN-12")
        problems += expect(condition.get("gate") in RELEASE_GATES, "CI_BLOCKING", scope,
                           f"gate must be one of {sorted(RELEASE_GATES)}", "NN-12")
        detectors = condition.get("detected_by")
        problems += expect(isinstance(detectors, list) and bool(detectors), "CI_BLOCKING", scope,
                           "a blocking condition nobody detects is not a control", "NN-12")
        for detector in detectors or []:
            problems += expect(detector in by_id, "CI_BLOCKING", scope,
                               f"unknown detecting stage '{detector}'", "NN-12")
    for cid in sorted(set(REQUIRED_BLOCKING_TOPICS) - seen):
        problems.append(Problem("CI_BLOCKING_MISSING", where,
                                f"the batch document requires a blocking condition for "
                                f"'{REQUIRED_BLOCKING_TOPICS[cid]}' ({cid})", "NN-12"))
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    rendered = cigen.render_all(root)
    for rel, expected in sorted(rendered.items()):
        budget.check(rel)
        path = root / rel
        if not path.is_file():
            problems.append(Problem("CI_MISSING", rel,
                                    "generated CI file is missing; run scripts/render-ci.py",
                                    "NN-12"))
        elif path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("CI_DRIFT", rel,
                                    "generated CI file differs from governance/ci-pipeline.json",
                                    "NN-12"))
    text = rendered[str(WORKFLOW)]
    for forbidden in FORBIDDEN_IN_WORKFLOW:
        if forbidden in text:
            problems.append(Problem("CI_UNSAFE_WORKFLOW", str(WORKFLOW),
                                    f"workflow must not contain '{forbidden}'", "NN-11"))
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- uses:") and "@" in stripped:
            ref = stripped.split("@", 1)[1].split()[0]
            if not ACTION_SHA.match(ref):
                problems.append(Problem("CI_ACTION_PIN", str(WORKFLOW),
                                        f"action reference '{ref}' is not a commit SHA", "NN-12"))
    return problems
