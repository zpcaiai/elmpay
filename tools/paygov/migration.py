"""B15 — migrating an existing project onto the payment platform.

The batch's principle is narrow and load-bearing: business orders stay where
they are, and only payment facts and payment actions move. Everything here
defends one of the ways that principle gets lost:

* an adapter that passes SKUs, quantities or shipping addresses through re-teaches
  the platform about orders, which is exactly what NN-01 forbids and FF-03 names;
* "dual write" is the phrase under which a project accidentally calls the
  provider twice. In every phase there is exactly one provider call per payment;
  the non-authoritative side writes a mirror of the same fact and holds no
  idempotency key;
* a phase with two authorities for payment facts has none, and reconciliation
  cannot say which side is wrong;
* a rollback that discards the other side's records is not a rollback, it is a
  second migration performed under pressure;
* a backfill that is not resumable will be re-run from the start after the first
  timeout, and a backfill verified by sampling proves existence, not
  conservation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

PLAN = Path("governance/migration-plan.json")
DOMAIN = Path("governance/domain-model.json")
API = Path("governance/api-contract.json")
BOUNDARIES = Path("governance/service-boundaries.json")

WRITE_MODES = ["legacy_only", "dual_write_legacy_authoritative",
               "dual_write_platform_authoritative", "platform_only"]
AUTHORITIES = {"legacy", "platform"}
BUSINESS_TERMS = ("sku", "item", "quantity", "inventory", "stock", "shipping",
                  "product", "coupon", "fulfil")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("migration-plan", "B15")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(PLAN)
    budget.check(where)
    try:
        plan = load_json(root / PLAN)
    except Exception as exc:
        return [Problem("MIG_UNREADABLE", where,
                        f"cannot read the migration plan: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(plan.get("schema_version", ""))), "MIG_VERSION_FIELD",
                       where, "schema_version must be semver", "NN-12")
    problems += expect(len(str(plan.get("principle") or "")) >= 20, "MIG_PRINCIPLE", where,
                       "the migration principle must be stated; without it every phase becomes "
                       "a negotiation", "NN-01")

    problems += _ownership(plan, root, where)
    problems += _legacy_access(plan, where)
    problems += _adapter(plan, root, where)
    problems += _dual_write(plan, where)
    problems += _backfill(plan, where)
    problems += _cutover(plan, where)
    problems += _phases(plan, where, budget)
    problems += _generated(root, budget)
    return problems


def _ownership(plan: dict, root: Path, where: str) -> list[Problem]:
    ownership = plan.get("ownership") or {}
    legacy = [str(x) for x in ownership.get("legacy_owns") or []]
    platform = [str(x) for x in ownership.get("platform_owns") or []]
    problems = list(expect(legacy, "MIG_OWNERSHIP", where,
                           "the plan must name what stays in the legacy project; an unnamed "
                           "boundary migrates by accident", "NN-01"))
    problems += expect(platform, "MIG_OWNERSHIP", where,
                       "the plan must name what moves to the platform", "NN-01")
    overlap = set(legacy) & set(platform)
    problems += expect(not overlap, "MIG_OWNERSHIP_OVERLAP", where,
                       f"{sorted(overlap)} appear on both sides of the split; a concept owned by "
                       f"both systems is owned by neither", "NN-01")

    try:
        domain = load_json(root / DOMAIN)
    except Exception:
        domain = {"entities": []}
    tables = {e.get("table") for e in domain.get("entities", [])}
    for name in legacy:
        problems += expect(name not in tables, "MIG_LEGACY_IN_PLATFORM", where,
                           f"'{name}' is declared legacy-owned but exists as a platform table; "
                           f"the business order has already crossed the line (FF-03)", "NN-01")
    for name in platform:
        problems += expect(name in tables, "MIG_PLATFORM_MISSING", where,
                           f"'{name}' is declared platform-owned but is not a platform table",
                           "NN-12")

    binding = ownership.get("binding") or {}
    problems += expect(binding.get("field") == "external_reference", "MIG_BINDING", where,
                       "the two systems must be bound by external_reference and nothing else",
                       "NN-01")
    problems += expect({"project_id", "external_reference"} <= set(binding.get("uniqueness") or []),
                       "MIG_BINDING", where,
                       "the binding must be unique per (project_id, external_reference); "
                       "otherwise one business order can bind to two payments", "NN-04")
    return problems


def _legacy_access(plan: dict, where: str) -> list[Problem]:
    access = plan.get("legacy_database_access") or {}
    problems = list(expect(access.get("allowed") is False, "MIG_LEGACY_DB_ACCESS", where,
                           "the platform must not connect to the legacy database (FF-01); a "
                           "read-only credential today is a join tomorrow", "NN-01"))
    problems += expect(len(str(access.get("policy") or "")) >= 10, "MIG_LEGACY_DB_ACCESS", where,
                       "state how business context reaches the platform instead", "NN-01")
    return problems


def _adapter(plan: dict, root: Path, where: str) -> list[Problem]:
    adapter = plan.get("adapter") or {}
    problems = list(expect(bool(adapter.get("owner")), "MIG_ADAPTER_OWNER", where,
                           "the adapter needs an owner", "NN-12"))
    problems += expect("旧系统" in str(adapter.get("location") or "")
                       or "legacy" in str(adapter.get("location") or "").lower(),
                       "MIG_ADAPTER_LOCATION", where,
                       "the adapter belongs in the legacy project; putting it in the platform "
                       "repository is how the platform starts understanding orders again",
                       "NN-01")

    try:
        contract = load_json(root / API)
        operations = {o.get("id") for o in contract.get("operations", [])}
    except Exception:
        operations = set()

    forbidden = [str(x).lower() for x in adapter.get("forbidden_passthrough") or []]
    problems += expect(any(term in " ".join(forbidden) for term in ("sku", "item")),
                       "MIG_ADAPTER_FORBIDDEN_LIST", where,
                       "the adapter's forbidden pass-through list must at least name order line "
                       "concepts; an empty list is not a boundary", "NN-01")

    entries = adapter.get("operations")
    problems += expect(isinstance(entries, list) and entries, "MIG_ADAPTER_OPERATIONS", where,
                       "the adapter must enumerate the operations it maps", "NN-12")
    for index, entry in enumerate(entries or []):
        scope = f"{where}#adapter[{index}]"
        if not isinstance(entry, dict):
            problems.append(Problem("MIG_SHAPE", scope, "each adapter operation must be an "
                                    "object", "NN-12"))
            continue
        target = entry.get("platform_operation")
        problems += expect(target in operations, "MIG_ADAPTER_OPERATION", scope,
                           f"'{target}' is not an operation in the API contract", "NN-12")
        problems += expect(entry.get("idempotency_source") == "external_reference",
                           "MIG_ADAPTER_IDEMPOTENCY", scope,
                           "the adapter must derive the idempotency key from the business "
                           "order's reference; a fresh key per retry is a second charge",
                           "NN-04")
        for field in entry.get("passes_through") or []:
            lowered = str(field).lower()
            leaks = [term for term in BUSINESS_TERMS if term in lowered]
            if leaks:
                problems.append(Problem(
                    "MIG_ADAPTER_LEAK", scope,
                    f"the adapter passes '{field}' to the platform; order line data must not "
                    f"cross the boundary (FF-03)", "NN-01"))
            problems += expect(lowered not in forbidden, "MIG_ADAPTER_LEAK", scope,
                               f"'{field}' is on the adapter's own forbidden list yet is passed "
                               f"through", "NN-01")
    return problems


def _dual_write(plan: dict, where: str) -> list[Problem]:
    dual = plan.get("dual_write") or {}
    problems = list(expect(int(dual.get("provider_calls_per_payment") or 0) == 1,
                           "MIG_DOUBLE_CHARGE", where,
                           "dual write means writing two records, not making two provider calls; "
                           "anything other than exactly one call per payment is a duplicate "
                           "charge by design", "NN-04"))
    detection = dual.get("divergence_detection") or {}
    problems += expect(bool(detection.get("compare_fields")), "MIG_DIVERGENCE", where,
                       "dual write without divergence detection is two systems drifting in "
                       "private", "NN-12")
    problems += expect("amount_minor" in (detection.get("compare_fields") or []),
                       "MIG_DIVERGENCE", where,
                       "the comparison must include the amount; a divergence that is not about "
                       "money is the only kind worth tolerating", "NN-05")
    problems += expect(0 < float(detection.get("budget_pct") or 0) <= 1, "MIG_DIVERGENCE", where,
                       "a divergence budget must exist and be small", "NN-12")
    problems += expect(int(detection.get("window_minutes") or 0) > 0, "MIG_DIVERGENCE", where,
                       "divergence detection needs a comparison window", "NN-12")
    problems += expect(len(str(detection.get("abort_rule") or "")) >= 10, "MIG_DIVERGENCE_ABORT",
                       where,
                       "there must be a rule that stops the migration; a divergence budget with "
                       "no abort rule is a metric, not a control", "NN-12")
    problems += expect(bool(detection.get("record_to")), "MIG_DIVERGENCE", where,
                       "divergences must land somewhere a human is accountable for", "NN-12")
    problems += expect(len(str(dual.get("policy") or "")) >= 20, "MIG_DUAL_WRITE_POLICY", where,
                       "write down what dual write does and does not mean", "NN-04")
    return problems


def _backfill(plan: dict, where: str) -> list[Problem]:
    backfill = plan.get("backfill") or {}
    problems = list(expect(backfill.get("idempotent") is True, "MIG_BACKFILL", where,
                           "the backfill must be idempotent; it will be re-run", "NN-04"))
    problems += expect(backfill.get("resumable") is True, "MIG_BACKFILL", where,
                       "the backfill must be resumable, otherwise the first timeout costs the "
                       "whole run", "NN-04")
    problems += expect(bool(backfill.get("checkpoint_field")), "MIG_BACKFILL", where,
                       "a resumable backfill needs a checkpoint field", "NN-04")
    problems += expect(backfill.get("read_only_on_legacy") is True, "MIG_BACKFILL_WRITES", where,
                       "the backfill must not write to the legacy system; a migration that "
                       "mutates its source cannot be re-run or audited", "NN-06")
    verification = backfill.get("verification") or {}
    methods = verification.get("method") or []
    problems += expect(any("sum" in str(m) for m in methods), "MIG_BACKFILL_VERIFICATION", where,
                       "verification must include a total, not only sampling; sampling proves "
                       "existence, totals prove conservation", "NN-06")
    problems += expect(bool(verification.get("tolerance")), "MIG_BACKFILL_VERIFICATION", where,
                       "state the tolerance explicitly", "NN-12")
    return problems


def _cutover(plan: dict, where: str) -> list[Problem]:
    cutover = plan.get("cutover") or {}
    problems = list(expect(cutover.get("granularity") == "project", "MIG_CUTOVER_GRANULARITY",
                           where,
                           "cutover must be per project; a global switch has no safe rollback "
                           "and no small blast radius", "NN-12"))
    switch = cutover.get("kill_switch") or {}
    problems += expect(bool(switch.get("scope")), "MIG_KILL_SWITCH", where,
                       "a kill switch needs a scope", "NN-12")
    problems += expect(0 < int(switch.get("max_activation_seconds") or 0) <= 300,
                       "MIG_KILL_SWITCH", where,
                       "the kill switch must act within minutes; one that takes a deploy is not "
                       "a kill switch", "NN-12")
    problems += expect(switch.get("requires_audit_event") is True, "MIG_KILL_SWITCH", where,
                       "activating the kill switch must leave an audit event", "NN-11")
    return problems


def _phases(plan: dict, where: str, budget: Budget) -> list[Problem]:
    phases = plan.get("phases")
    if not isinstance(phases, list) or not phases:
        return [Problem("MIG_SHAPE", where, "'phases' must be a non-empty list", "NN-12")]

    problems: list[Problem] = []
    seen: set = set()
    last_index = -1
    for index, phase in enumerate(phases):
        scope = f"{where}#{index}"
        if not isinstance(phase, dict):
            problems.append(Problem("MIG_SHAPE", scope, "each phase must be an object", "NN-12"))
            continue
        budget.check(scope)
        pid = phase.get("id")
        scope = f"{where}#{pid}"
        problems += expect(pid not in seen, "MIG_PHASE_DUPLICATE", scope,
                           f"duplicate phase '{pid}'", "NN-12")
        seen.add(pid)

        mode = phase.get("write_mode")
        problems += expect(mode in WRITE_MODES, "MIG_WRITE_MODE", scope,
                           f"write mode '{mode}' is not one of {WRITE_MODES}", "NN-12")
        if mode in WRITE_MODES:
            position = WRITE_MODES.index(mode)
            problems += expect(position > last_index, "MIG_PHASE_ORDER", scope,
                               f"phase '{pid}' does not advance the write mode; phases must move "
                               f"forward, and a plan that can go sideways will", "NN-12")
            last_index = max(last_index, position)

        authority = phase.get("authoritative_for_payment_facts")
        problems += expect(authority in AUTHORITIES, "MIG_AUTHORITY", scope,
                           f"exactly one system must be authoritative for payment facts in every "
                           f"phase; got {authority!r}", "NN-12")
        if mode == "legacy_only":
            problems += expect(authority == "legacy", "MIG_AUTHORITY", scope,
                               "in legacy_only the legacy system is authoritative", "NN-12")
        if mode == "platform_only":
            problems += expect(authority == "platform", "MIG_AUTHORITY", scope,
                               "in platform_only the platform is authoritative", "NN-12")

        problems += expect(bool(phase.get("entry_criteria")), "MIG_PHASE_CRITERIA", scope,
                           "a phase needs entry criteria", "NN-12")
        problems += expect(bool(phase.get("exit_criteria")), "MIG_PHASE_CRITERIA", scope,
                           "a phase needs exit criteria; without them 'we are in phase 2' is an "
                           "opinion", "NN-12")
        problems += expect(bool(phase.get("evidence_gate")), "MIG_PHASE_EVIDENCE", scope,
                           "advancing a phase must be gated on evidence, not on confidence",
                           "NN-12")
        problems += expect(len(str(phase.get("notes") or "")) >= 12, "MIG_PHASE_NOTES", scope,
                           "each phase must say what it is actually for", "NN-12")

        rollback = phase.get("rollback") or {}
        problems += expect(bool(rollback.get("action")), "MIG_ROLLBACK", scope,
                           "every phase needs a rollback action", "NN-12")
        problems += expect(rollback.get("payment_facts_preserved") is True,
                           "MIG_ROLLBACK_DESTRUCTIVE", scope,
                           f"the rollback for '{pid}' does not preserve payment facts; a rollback "
                           f"that discards records is a second migration performed under "
                           f"pressure", "NN-06")
        problems += expect(len(str(rollback.get("reason") or "")) >= 10, "MIG_ROLLBACK", scope,
                           "say why the rollback is safe", "NN-12")

    problems += expect(WRITE_MODES[0] in {p.get("write_mode") for p in phases
                                          if isinstance(p, dict)},
                       "MIG_PHASE_ORDER", where,
                       "the plan must start from legacy_only; a migration that starts by writing "
                       "to both has no baseline to compare against", "NN-12")
    problems += expect(WRITE_MODES[-1] in {p.get("write_mode") for p in phases
                                           if isinstance(p, dict)},
                       "MIG_PHASE_ORDER", where,
                       "the plan must end at platform_only, otherwise it is not a migration",
                       "NN-12")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .miggen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("MIG_GENERATED_MISSING", rel,
                                    "generated migration artefact is missing; run "
                                    "scripts/render-migration.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("MIG_GENERATED", rel,
                                    f"the artefact cannot be derived from the plan: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("MIG_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the plan; run "
                                    "scripts/render-migration.py", "NN-12"))
    return problems
