"""B06 — evidence framework gate.

The batch orchestrator checks that evidence *exists* and hashes correctly. This
validator checks that the evidence is *about the batch it claims to be about*:
traceability entries must point at files that exist, artefact lists must match
the completion file, the plan must actually contain a rollback and a threat
section, and each batch must have run the command classes that make its
evidence meaningful (test summary, governance gate, fail-closed proof,
timeout proof, idempotency proof, environment fingerprint).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .orchestration import Programme
from .repo import Budget, load_json
from .structs import SEMVER, expect

POLICY = Path("governance/evidence-policy.json")
EVIDENCE = Path("evidence")
# Plan sections are matched by title keyword rather than by number so that a
# batch may add or reorder sections without weakening the requirement that the
# section itself exists.
PLAN_HEADING = re.compile(r"^##\s*\d+\.\s*(.+)$", re.MULTILINE)


def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget(seconds=120).start()
    where = str(POLICY)
    try:
        policy: Any = load_json(root / POLICY, budget)
        programme = Programme(root, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("EVIDENCE_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(policy.get("schema_version", "")))),
                       "EVIDENCE_VERSION", where, "schema_version must be semantic version",
                       "NN-12")

    completion_dir = root / "evidence" / "completion"
    batches = sorted(p.stem for p in completion_dir.glob("*.json")) if completion_dir.is_dir() \
        else []
    if not batches:
        return problems + [Problem("EVIDENCE_EMPTY", str(EVIDENCE),
                                   "no completed batch evidence found", "NN-12")]

    for batch in batches:
        budget.check(batch)
        problems += _batch(root, batch, policy, programme)
    problems += _principals(root, policy, batches, where)
    return problems


def _batch(root: Path, batch: str, policy: dict, programme: Programme) -> list[Problem]:
    base = root / EVIDENCE / batch
    scope = str(EVIDENCE / batch)
    problems: list[Problem] = []

    if batch not in programme.batches:
        return [Problem("EVIDENCE_UNKNOWN_BATCH", scope,
                        f"'{batch}' has a completion file but is not in the manifest", "NN-12")]

    for name in policy["required_batch_files"]:
        problems += expect((base / name).is_file(), "EVIDENCE_FILE", scope,
                           f"missing required evidence file '{name}'", "NN-12")
    for name in policy["required_batch_dirs"]:
        problems += expect((base / name).is_dir(), "EVIDENCE_DIR", scope,
                           f"missing required evidence directory '{name}'", "NN-12")

    plan = base / "plan.md"
    if plan.is_file():
        headings = PLAN_HEADING.findall(plan.read_text(encoding="utf-8"))
        for section in policy["required_plan_sections"]:
            problems += expect(any(section in heading for heading in headings),
                               "EVIDENCE_PLAN_SECTION", f"{scope}/plan.md",
                               f"plan has no section covering '{section}'", "NN-12")

    spec = base / "commands.spec.json"
    if spec.is_file():
        try:
            commands = json.loads(spec.read_text(encoding="utf-8"))["commands"]
        except Exception as exc:
            problems.append(Problem("EVIDENCE_SPEC", f"{scope}/commands.spec.json",
                                    f"unreadable command spec: {exc}", "NN-12"))
            commands = []
        joined = "\n".join(c.get("command", "") for c in commands)
        for required in policy["required_command_classes"]:
            problems += expect(required["match"] in joined, "EVIDENCE_COMMAND_CLASS",
                               f"{scope}/commands.spec.json",
                               f"no command covers '{required['id']}' ({required['purpose']})",
                               "NN-12")

    problems += _traceability(root, base, scope, policy)
    problems += _artifacts(root, base, scope, batch, programme)
    return problems


def _traceability(root: Path, base: Path, scope: str, policy: dict) -> list[Problem]:
    path = base / "traceability.json"
    if not path.is_file():
        return []
    problems: list[Problem] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [Problem("EVIDENCE_TRACE", f"{scope}/traceability.json", str(exc), "NN-12")]
    for section, key in policy["traceability_path_keys"].items():
        for entry in data.get(section, []):
            rel = entry.get(key) if isinstance(entry, dict) else None
            if not isinstance(rel, str):
                problems.append(Problem("EVIDENCE_TRACE", f"{scope}/traceability.json",
                                        f"{section} entry has no '{key}'", "NN-12"))
                continue
            target = root / rel
            problems += expect(target.exists(), "EVIDENCE_TRACE_DANGLING",
                               f"{scope}/traceability.json",
                               f"{section} references '{rel}' which does not exist", "NN-12")
    return problems


def _artifacts(root: Path, base: Path, scope: str, batch: str,
               programme: Programme) -> list[Problem]:
    listing = base / "artifacts.json"
    completion = programme.completion_path(batch)
    if not listing.is_file() or not completion.is_file():
        return []
    problems: list[Problem] = []
    try:
        declared = set(json.loads(listing.read_text(encoding="utf-8")))
        recorded = {a["path"] for a in
                    json.loads(completion.read_text(encoding="utf-8"))["artifacts"]}
    except Exception as exc:
        return [Problem("EVIDENCE_ARTIFACT", f"{scope}/artifacts.json", str(exc), "NN-12")]
    for rel in sorted(declared - recorded):
        problems.append(Problem("EVIDENCE_ARTIFACT", f"{scope}/artifacts.json",
                                f"'{rel}' is declared but absent from the completion file; "
                                f"re-run scripts/finish-batch.py", "NN-12"))
    for rel in sorted(recorded - declared):
        problems.append(Problem("EVIDENCE_ARTIFACT", f"{scope}/artifacts.json",
                                f"completion file records '{rel}' which is not declared", "NN-12"))
    for rel in sorted(declared):
        problems += expect((root / rel).is_file(), "EVIDENCE_ARTIFACT",
                           f"{scope}/artifacts.json", f"declared artefact '{rel}' does not exist",
                           "NN-12")
    return problems


def _principals(root: Path, policy: dict, batches: list[str], where: str) -> list[Problem]:
    expected = policy.get("principals", {})
    problems: list[Problem] = []
    for batch in batches:
        path = root / "evidence" / "completion" / f"{batch}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for role in ("executor", "reviewer"):
            if role in expected:
                problems += expect(data.get(role) == expected[role], "EVIDENCE_PRINCIPAL",
                                   str(path.relative_to(root)),
                                   f"{role} must be '{expected[role]}' as declared in the "
                                   f"evidence policy", "NN-11")
        problems += expect(data.get("executor") != data.get("reviewer"), "EVIDENCE_PRINCIPAL",
                           str(path.relative_to(root)),
                           "executor and reviewer must differ (four-eyes)", "NN-11")
    return problems
