"""B22 — ASVS, API Security and MASVS mapped to rules that actually run.

A security baseline usually arrives as a spreadsheet, and a spreadsheet cannot
tell you whether the control it claims exists. This one is checked:

* a requirement enforced by ``gate_rule`` must name rule codes this repository
  *actually emits* — ``BASE_RULE_UNKNOWN`` fires on a mapping to a code that no
  validator produces, which is the single most common way a compliance matrix
  becomes fiction;
* a requirement enforced by ``test`` must name a test that exists, down to the
  method: ``file::Class::test_method`` is resolved by parsing the file, so
  renaming or deleting the test breaks the claim instead of silently orphaning
  it;
* a requirement that is not enforced must say so as an ``accepted_gap``, with an
  owner and the batch that will revisit it, and the number of those is capped.
  Without a cap, "accepted gap" is just a longer way of writing "ignored".

The mobile requirements are all gaps on purpose: this platform has no first-party
mobile application, and marking MASVS items "compliant" because they do not
apply would be the exact dishonesty this file exists to prevent.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from . import rulecov
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import BATCH_ID, SEMVER, expect

BASELINE = Path("governance/security-baseline.json")
SHIPPED_ROOT = Path(__file__).resolve().parents[2]

REQUIREMENT_ID = re.compile(r"^[A-Z][A-Z0-9]*-[0-9]+(\.[0-9]+){0,2}$|^MASVS-[A-Z]+-[0-9]+$")
KINDS = {"gate_rule", "test", "accepted_gap"}
LEVELS = {"L1", "L2", "L3"}
APPLICABILITY = {"backend", "api", "mobile", "supply_chain", "all"}
# MASVS applies to a first-party mobile app. Claiming compliance for an app that
# does not exist is worse than recording the gap.
NOT_APPLICABLE = {"mobile"}


VALIDATOR = ("security-baseline", "B22")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(BASELINE)
    budget.check(where)
    try:
        model = load_json(root / BASELINE)
    except Exception as exc:
        return [Problem("BASE_UNREADABLE", where,
                        f"cannot read the security baseline: {exc}", "NN-12")]
    if not isinstance(model, dict):
        return [Problem("BASE_SHAPE", where, "the baseline must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "BASE_VERSION_FIELD", where, "schema_version must be semver", "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "BASE_PRINCIPLE", where,
                       "say what makes this different from a spreadsheet", "NN-12")

    standards, problems_ = _standards(model, where)
    problems += problems_
    # Resolved against the *running* gate, not against the tree being scanned.
    # The claim a mapping makes is "this rule code exists in the gate that will
    # check my repository"; a fixture or an exported subset that ships no
    # validators does not make that claim false, and pretending otherwise would
    # make every fixture-based test fail for a reason that has nothing to do
    # with the baseline.
    emitted = set(rulecov.emitted_codes(SHIPPED_ROOT, budget))
    problems += _requirements(model, root, where, standards, emitted, budget)
    problems += _coverage(model, where)
    problems += _generated(root, budget)
    return problems


def _standards(model: dict, where: str) -> tuple[set[str], list[Problem]]:
    entries = model.get("standards")
    if not isinstance(entries, list) or not entries:
        return set(), [Problem("BASE_SHAPE", where, "standards must be a non-empty list",
                               "NN-12")]
    problems: list[Problem] = []
    known: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("BASE_SHAPE", where, "each standard must be an object",
                                    "NN-12"))
            continue
        sid = str(entry.get("id") or "")
        problems += expect(bool(sid), "BASE_STANDARD_ID", where, "a standard needs an id",
                           "NN-12")
        problems += expect(bool(str(entry.get("version") or "")), "BASE_STANDARD_VERSION",
                           f"{where}#{sid}",
                           f"standard '{sid}' has no version; 'we follow ASVS' without a version "
                           f"is not a claim anyone can check", "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "BASE_STANDARD_NOTES",
                           f"{where}#{sid}", "say how this standard applies here", "NN-12")
        known.add(sid)
    return known, problems


def _requirements(model: dict, root: Path, where: str, standards: set[str],
                  emitted: set[str], budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    entries = model.get("requirements")
    if not isinstance(entries, list) or not entries:
        return [Problem("BASE_SHAPE", where, "requirements must be a non-empty list", "NN-12")]
    seen: set[str] = set()
    covered_standards: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("BASE_SHAPE", where, "each requirement must be an object",
                                    "NN-12"))
            continue
        rid = str(entry.get("id") or "")
        scope = f"{where}#{rid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(REQUIREMENT_ID.match(rid)), "BASE_REQUIREMENT_ID", scope,
                           f"requirement id '{rid}' does not look like a standard reference",
                           "NN-12")
        problems += expect(rid not in seen, "BASE_REQUIREMENT_DUPLICATE", scope,
                           f"requirement '{rid}' is declared twice", "NN-12")
        seen.add(rid)
        standard = str(entry.get("standard") or "")
        problems += expect(standard in standards, "BASE_STANDARD_UNKNOWN", scope,
                           f"'{rid}' belongs to unregistered standard '{standard}'", "NN-12")
        covered_standards.add(standard)
        problems += expect(entry.get("level") in LEVELS, "BASE_LEVEL", scope,
                           f"level must be one of {sorted(LEVELS)}", "NN-12")
        problems += expect(entry.get("applicability") in APPLICABILITY, "BASE_APPLICABILITY",
                           scope, f"applicability must be one of {sorted(APPLICABILITY)}",
                           "NN-12")
        problems += expect(len(str(entry.get("title") or "")) >= 4, "BASE_TITLE", scope,
                           "a requirement needs its own title", "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "BASE_NOTES", scope,
                           "say how this is enforced here, in this repository", "NN-12")
        problems += _enforcement(entry, root, scope, emitted, budget)
    for standard in sorted(standards):
        problems += expect(standard in covered_standards, "BASE_STANDARD_UNUSED", where,
                           f"standard '{standard}' is registered but no requirement cites it",
                           "NN-12")
    return problems


def _enforcement(entry: dict, root: Path, scope: str, emitted: set[str],
                 budget: Budget) -> list[Problem]:
    enforcement = entry.get("enforcement")
    if not isinstance(enforcement, dict):
        return [Problem("BASE_SHAPE", scope, "enforcement must be an object", "NN-12")]
    kind = enforcement.get("kind")
    problems = list(expect(kind in KINDS, "BASE_ENFORCEMENT_KIND", scope,
                           f"enforcement kind must be one of {sorted(KINDS)}", "NN-12"))
    refs = enforcement.get("refs")
    if not isinstance(refs, list):
        return problems + [Problem("BASE_SHAPE", scope, "refs must be a list", "NN-12")]

    if kind == "gate_rule":
        problems += expect(bool(refs), "BASE_NO_ENFORCEMENT", scope,
                           "a requirement enforced by a gate rule must name at least one",
                           "NN-12")
        for ref in refs:
            problems += expect(ref in emitted, "BASE_RULE_UNKNOWN", scope,
                               f"'{ref}' is not a rule code any validator emits; a mapping to a "
                               f"rule that does not exist is how a compliance matrix becomes "
                               f"fiction", "NN-12")
    elif kind == "test":
        problems += expect(bool(refs), "BASE_NO_ENFORCEMENT", scope,
                           "a requirement enforced by a test must name at least one", "NN-12")
        for ref in refs:
            problems += _test_reference(root, scope, str(ref), budget)
    elif kind == "accepted_gap":
        problems += expect(not refs, "BASE_GAP_WITH_REFS", scope,
                           "an accepted gap must not also claim enforcement", "NN-12")
        problems += expect(len(str(enforcement.get("owner") or "")) >= 4, "BASE_GAP_NO_OWNER",
                           scope, "an accepted gap needs an owner, or nobody closes it", "NN-11")
        review = str(enforcement.get("review_batch") or "")
        problems += expect(bool(BATCH_ID.match(review)), "BASE_GAP_NO_REVIEW", scope,
                           f"an accepted gap needs the batch that revisits it, got '{review}'; "
                           f"a gap with no review date is a decision to never look again",
                           "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 12, "BASE_GAP_NO_REASON", scope,
                           "an accepted gap must say why it is acceptable", "NN-11")
    return problems


def _test_reference(root: Path, scope: str, ref: str, budget: Budget) -> list[Problem]:
    """Resolve ``path::Class::method`` against the actual test file."""
    parts = ref.split("::")
    rel = parts[0]
    path = root / rel
    budget.check(rel)
    if not path.is_file():
        return [Problem("BASE_TEST_MISSING", scope,
                        f"test file '{rel}' does not exist", "NN-12")]
    if len(parts) == 1:
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    except SyntaxError as exc:
        return [Problem("BASE_TEST_MISSING", scope,
                        f"cannot parse '{rel}': {exc.msg}", "NN-12")]
    node: ast.AST = tree
    for part in parts[1:]:
        found = None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef)) and child.name == part:
                found = child
                break
        if found is None:
            return [Problem("BASE_TEST_MISSING", scope,
                            f"'{ref}' names '{part}', which does not exist; a baseline that "
                            f"points at a deleted test claims a control nobody runs", "NN-12")]
        node = found
    return []


def _coverage(model: dict, where: str) -> list[Problem]:
    policy = model.get("coverage_policy")
    if not isinstance(policy, dict):
        return [Problem("BASE_SHAPE", where, "coverage_policy must be an object", "NN-12")]
    requirements = [r for r in (model.get("requirements") or []) if isinstance(r, dict)]
    applicable = [r for r in requirements if r.get("applicability") not in NOT_APPLICABLE]
    enforced = [r for r in applicable
                if (r.get("enforcement") or {}).get("kind") in {"gate_rule", "test"}]
    gaps = [r for r in requirements
            if (r.get("enforcement") or {}).get("kind") == "accepted_gap"]

    minimum = float(policy.get("minimum_covered_ratio") or 0)
    problems = list(expect(0 < minimum <= 1, "BASE_COVERAGE_POLICY", where,
                           "minimum_covered_ratio must be a ratio above zero", "NN-12"))
    problems += expect(policy.get("gap_requires_owner") is True, "BASE_COVERAGE_POLICY", where,
                       "gaps must require an owner", "NN-11")
    problems += expect(policy.get("gap_requires_review_batch") is True, "BASE_COVERAGE_POLICY",
                       where, "gaps must require a review batch", "NN-11")
    maximum = int(policy.get("max_accepted_gaps") or 0)
    problems += expect(maximum > 0, "BASE_COVERAGE_POLICY", where,
                       "max_accepted_gaps must be a positive cap", "NN-11")

    if applicable:
        ratio = len(enforced) / len(applicable)
        problems += expect(ratio >= minimum - 1e-9, "BASE_COVERAGE_BELOW_FLOOR", where,
                           f"{len(enforced)}/{len(applicable)} applicable requirements are "
                           f"enforced ({ratio:.0%}), below the {minimum:.0%} floor", "NN-12")
    problems += expect(len(gaps) <= maximum, "BASE_TOO_MANY_GAPS", where,
                       f"{len(gaps)} accepted gaps exceed the cap of {maximum}; without a cap, "
                       f"'accepted gap' is just a longer way of writing 'ignored'", "NN-11")
    for requirement in requirements:
        if requirement.get("applicability") in NOT_APPLICABLE:
            problems += expect(
                (requirement.get("enforcement") or {}).get("kind") == "accepted_gap",
                "BASE_FALSE_COMPLIANCE", f"{where}#{requirement.get('id')}",
                f"'{requirement.get('id')}' applies to a first-party mobile app, which does not "
                f"exist here; claiming enforcement for it would be a false claim", "NN-12")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .baselinegen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("BASE_GENERATED", rel,
                                    f"cannot generate {rel}: {exc}", "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("BASE_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/security-baseline.json "
                                    f"but does not exist; run scripts/render-baseline.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("BASE_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the baseline generates", "NN-12"))
    return problems
