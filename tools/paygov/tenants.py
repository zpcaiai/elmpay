"""B24 — organisation, tenant, project and environment registry.

Multi-tenant platforms rarely fail at the front door. They fail at three edges,
and every rule here is aimed at one of them:

* **suspension** — ``TENANT_SUSPENDED_BLOCKS_REFUNDS`` exists because the
  instinctive implementation of "suspend this merchant" switches everything off,
  including the refunds their customers are already owed and the provider
  callbacks that decide whether money moved. Suspension must stop *new* money,
  not in-flight money;
* **closure** — ``TENANT_CLOSE_BEFORE_SETTLEMENT`` and
  ``TENANT_LEDGER_NOT_RETAINED``: destroying a tenant's key before their
  settlement completes locks their money on our books, and deleting the record
  of what the platform did is not a deletion we are allowed to make;
* **environments** — ``TENANT_ENV_SHARES_KEYS``. A test credential that works in
  live is the single most expensive one-line bug in this domain, and it is
  always introduced as a convenience.

Identifiers get their own rule (``TENANT_ID_NOT_OPAQUE``) because encoding a
name, a country or a counter into a tenant id hands business intelligence to
anyone who can read a URL, and turns "rename" into "change the primary key".
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

TENANTS = Path("governance/tenant-registry.json")
DATA = Path("governance/data-architecture.json")
KEYS = Path("governance/key-management.json")
CERTS = Path("governance/certificates.json")
AUDIT = Path("governance/audit-log.json")

LEVELS = ["organisation", "tenant", "project", "environment"]
STATES = ["draft", "active", "suspended", "offboarding", "closed"]
CAPABILITIES = ("accept_payments", "issue_refunds", "receive_webhooks", "settle", "read_data")
# Anything that decides whether money already in flight completes.
IN_FLIGHT = ("issue_refunds", "receive_webhooks", "settle")
QUOTA_SCOPES = {"organisation", "tenant", "project", "environment"}


VALIDATOR = ("tenant-registry", "B24")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(TENANTS)
    budget.check(where)
    try:
        model = load_json(root / TENANTS)
    except Exception as exc:
        return [Problem("TENANT_UNREADABLE", where,
                        f"cannot read the tenant registry: {exc}", "NN-06")]
    if not isinstance(model, dict):
        return [Problem("TENANT_SHAPE", where, "the registry must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "TENANT_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "TENANT_PRINCIPLE", where,
                       "say where multi-tenant platforms actually break", "NN-06")
    problems += _hierarchy(model, where, budget)
    problems += _identifier(model, where)
    problems += _environments(model, root, where, budget)
    problems += _lifecycle(model, where, budget)
    problems += _capabilities(model, where, budget)
    problems += _isolation(model, root, where, budget)
    problems += _quotas(model, where, budget)
    problems += _offboarding(model, where)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _hierarchy(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("hierarchy")
    if not isinstance(entries, list) or not entries:
        return [Problem("TENANT_SHAPE", where, "hierarchy must be a non-empty list", "NN-06")]
    problems: list[Problem] = []
    levels = [str(e.get("level")) for e in entries if isinstance(e, dict)]
    problems += expect(levels == LEVELS, "TENANT_HIERARCHY", where,
                       f"the hierarchy must be {LEVELS} in order, got {levels}", "NN-06")
    prefixes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("TENANT_SHAPE", where, "each level must be an object",
                                    "NN-12"))
            continue
        level = str(entry.get("level"))
        scope = f"{where}#{level}"
        budget.check(scope)
        prefix = str(entry.get("id_prefix") or "")
        problems += expect(bool(re.match(r"^[a-z]{3}$", prefix)), "TENANT_PREFIX", scope,
                           f"'{level}' needs a three-letter id prefix, got '{prefix}'", "NN-12")
        problems += expect(prefix not in prefixes, "TENANT_PREFIX", scope,
                           f"prefix '{prefix}' is used twice; ambiguous ids make it impossible "
                           f"to tell what an identifier refers to", "NN-12")
        prefixes.add(prefix)
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "TENANT_LEVEL_NOTES", scope,
                           "say what boundary this level draws", "NN-06")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        parent = entry.get("parent")
        expected_parent = LEVELS[index - 1] if index else None
        problems += expect(parent == expected_parent, "TENANT_HIERARCHY",
                           f"{where}#{entry.get('level')}",
                           f"parent must be {expected_parent!r}, got {parent!r}", "NN-06")
    return problems


def _identifier(model: dict, where: str) -> list[Problem]:
    identifier = model.get("identifier")
    if not isinstance(identifier, dict):
        return [Problem("TENANT_SHAPE", where, "identifier must be an object", "NN-06")]
    pattern = str(identifier.get("pattern") or "")
    problems = list(expect(bool(pattern), "TENANT_ID_PATTERN", where,
                           "identifiers need a pattern", "NN-12"))
    if pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            problems.append(Problem("TENANT_ID_PATTERN", where,
                                    f"identifier pattern does not compile: {exc}", "NN-12"))
    problems += expect(identifier.get("opaque") is True, "TENANT_ID_NOT_OPAQUE", where,
                       "identifiers must be opaque; a name or a counter inside an id is business "
                       "intelligence handed to anyone who can read a URL", "NN-06")
    problems += expect(identifier.get("immutable") is True, "TENANT_ID_MUTABLE", where,
                       "identifiers must be immutable, or renaming becomes a primary-key change",
                       "NN-06")
    return problems


def _environments(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("environments")
    if not isinstance(entries, list) or len(entries) < 2:
        return [Problem("TENANT_SHAPE", where,
                        "at least a live and a test environment must be declared", "NN-06")]
    problems: list[Problem] = []
    live = [e for e in entries if isinstance(e, dict) and e.get("handles_real_money")]
    problems += expect(len(live) == 1, "TENANT_ENV_MONEY", where,
                       f"exactly one environment may handle real money, got {len(live)}",
                       "NN-06")
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        eid = str(entry.get("id"))
        scope = f"{where}#{eid}"
        budget.check(scope)
        problems += expect(not entry.get("shares_keys_with"), "TENANT_ENV_SHARES_KEYS", scope,
                           f"environment '{eid}' shares keys with "
                           f"{entry.get('shares_keys_with')}; a test credential that works in "
                           f"live is the most expensive convenience in this domain", "NN-07")
        problems += expect(not entry.get("shares_data_with"), "TENANT_ENV_SHARES_DATA", scope,
                           f"environment '{eid}' shares data with "
                           f"{entry.get('shares_data_with')}", "NN-06")
    budget.check(str(CERTS))
    try:
        certs = load_json(root / CERTS)
        forbidden = (certs.get("forbidden") or {}).get("shared_key_across_environments")
    except Exception:
        forbidden = None
    problems += expect(forbidden is False, "TENANT_ENV_SHARES_KEYS", where,
                       "B21 must also forbid sharing key material across environments; one of "
                       "the two saying so is not a control", "NN-07")
    return problems


def _lifecycle(model: dict, where: str, budget: Budget) -> list[Problem]:
    lifecycle = model.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return [Problem("TENANT_SHAPE", where, "lifecycle must be an object", "NN-06")]
    states = list(lifecycle.get("states") or [])
    problems = list(expect(states == STATES, "TENANT_STATES", where,
                           f"lifecycle states must be {STATES}, got {states}", "NN-06"))
    problems += expect(lifecycle.get("initial") == "draft", "TENANT_INITIAL_STATE", where,
                       "a tenant must start in draft; starting active means a tenant can take "
                       "money before anyone verified who they are", "NN-06")
    problems += expect(list(lifecycle.get("terminal") or []) == ["closed"],
                       "TENANT_TERMINAL_STATE", where, "only 'closed' may be terminal", "NN-06")

    transitions = lifecycle.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return problems + [Problem("TENANT_SHAPE", where,
                                   "transitions must be a non-empty list", "NN-06")]
    seen: set[tuple[str, str]] = set()
    for entry in transitions:
        if not isinstance(entry, dict):
            problems.append(Problem("TENANT_SHAPE", where, "each transition must be an object",
                                    "NN-12"))
            continue
        source, target = str(entry.get("from")), str(entry.get("to"))
        scope = f"{where}#{source}->{target}"
        budget.check(scope)
        problems += expect(source in states and target in states, "TENANT_TRANSITION_UNKNOWN",
                           scope, f"transition references unknown state(s)", "NN-06")
        problems += expect((source, target) not in seen, "TENANT_TRANSITION_DUPLICATE", scope,
                           "transition declared twice", "NN-12")
        seen.add((source, target))
        requires = set(entry.get("requires") or [])
        problems += expect(bool(requires), "TENANT_TRANSITION_UNGUARDED", scope,
                           "a lifecycle transition with no requirement is a state change anybody "
                           "can make for no stated reason", "NN-13")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "TENANT_TRANSITION_NOTES",
                           scope, "say why this transition is guarded this way", "NN-06")
        if source == "draft" and target == "active":
            problems += expect("kyb_verified" in requires, "TENANT_ACTIVATION_UNVERIFIED", scope,
                               "activation must require KYB verification", "NN-14")
        if target == "active" and source == "suspended":
            problems += expect("second_approver" in requires, "TENANT_UNSUSPEND_SINGLE_PERSON",
                               scope,
                               "un-suspending needs a second person; suspension usually follows "
                               "a risk or compliance decision, and one person reversing it is "
                               "one person overruling that decision", "NN-03")
        if target == "closed":
            problems += expect("settlement_complete" in requires,
                               "TENANT_CLOSE_BEFORE_SETTLEMENT", scope,
                               "closing before settlement completes locks the tenant's money on "
                               "our books", "NN-06")
            problems += expect("kek_destroyed" in requires, "TENANT_CLOSE_WITHOUT_SHREDDING",
                               scope, "closing must destroy the tenant key", "NN-06")

    reachable = {"draft"}
    changed = True
    while changed:
        changed = False
        for entry in transitions:
            if isinstance(entry, dict) and str(entry.get("from")) in reachable:
                target = str(entry.get("to"))
                if target not in reachable:
                    reachable.add(target)
                    changed = True
    for state in states:
        problems += expect(state in reachable, "TENANT_STATE_UNREACHABLE", where,
                           f"state '{state}' cannot be reached from draft", "NN-06")
    return problems


def _capabilities(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("capability_matrix")
    if not isinstance(entries, list) or not entries:
        return [Problem("TENANT_NO_CAPABILITY_MATRIX", where,
                        "without a capability matrix, 'suspended' means whatever the first "
                        "implementer assumed", "NN-06")]
    problems: list[Problem] = []
    covered: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("TENANT_SHAPE", where, "each row must be an object",
                                    "NN-12"))
            continue
        state = str(entry.get("state"))
        scope = f"{where}#{state}"
        budget.check(scope)
        covered.add(state)
        for capability in CAPABILITIES:
            problems += expect(isinstance(entry.get(capability), bool),
                               "TENANT_CAPABILITY_MISSING", scope,
                               f"'{state}' does not say whether {capability} is allowed",
                               "NN-06")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "TENANT_CAPABILITY_NOTES",
                           scope, "say what this state means operationally", "NN-06")
        if state == "draft":
            problems += expect(entry.get("accept_payments") is False, "TENANT_DRAFT_TAKES_MONEY",
                               scope, "a draft tenant must not take payments", "NN-14")
        if state in {"suspended", "offboarding"}:
            for capability in IN_FLIGHT:
                problems += expect(entry.get(capability) is True,
                                   "TENANT_SUSPENDED_BLOCKS_REFUNDS", scope,
                                   f"'{state}' must still allow {capability}: suspension stops "
                                   f"new money, not money already in flight — otherwise the "
                                   f"payers of a suspended merchant cannot get their money back",
                                   "NN-01")
            problems += expect(entry.get("accept_payments") is False,
                               "TENANT_SUSPENDED_TAKES_MONEY", scope,
                               f"'{state}' must not accept new payments", "NN-06")
        if state == "closed":
            for capability in CAPABILITIES:
                problems += expect(entry.get(capability) is False, "TENANT_CLOSED_ACTIVE", scope,
                                   f"a closed tenant must not still be able to {capability}",
                                   "NN-06")
    for state in STATES:
        problems += expect(state in covered, "TENANT_CAPABILITY_MISSING", where,
                           f"state '{state}' has no capability row", "NN-06")
    return problems


def _isolation(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    isolation = model.get("isolation")
    if not isinstance(isolation, dict):
        return [Problem("TENANT_SHAPE", where, "isolation must be an object", "NN-06")]
    problems = list(expect(isolation.get("cross_tenant_reference_allowed") is False,
                           "TENANT_CROSS_REFERENCE", where,
                           "cross-tenant references must stay forbidden", "NN-06"))
    problems += expect(isolation.get("row_level_security_required") is True,
                       "TENANT_NO_RLS", where, "row level security must be required", "NN-06")

    key_id = str(isolation.get("per_tenant_kek") or "")
    budget.check(str(KEYS))
    try:
        keys = load_json(root / KEYS)
        by_id = {str(k.get("id")): k for k in (keys.get("keys") or []) if isinstance(k, dict)}
    except Exception:
        by_id = {}
    entry = by_id.get(key_id)
    problems += expect(entry is not None, "TENANT_KEK_UNKNOWN", where,
                       f"the per-tenant KEK '{key_id}' is not managed in "
                       f"governance/key-management.json", "NN-07")
    if entry is not None:
        problems += expect(entry.get("tenant_scoped") is True, "TENANT_KEK_NOT_SCOPED", where,
                           f"'{key_id}' is not tenant scoped, so destroying it would erase every "
                           f"tenant at once", "NN-06")

    budget.check(str(DATA))
    try:
        data = load_json(root / DATA)
        tables = [t for t in (data.get("tables") or []) if isinstance(t, dict)]
    except Exception:
        tables = []
    unguarded = [str(t.get("table")) for t in tables
                 if t.get("tenant_scoped") and t.get("rls") is False]
    problems += expect(not unguarded, "TENANT_NO_RLS", where,
                       f"tenant-scoped tables without row level security: {sorted(unguarded)}",
                       "NN-06")
    return problems


def _quotas(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("quotas")
    if not isinstance(entries, list) or not entries:
        return [Problem("TENANT_NO_QUOTAS", where,
                        "quotas must exist; without them one tenant's traffic is every other "
                        "tenant's outage", "NN-06")]
    problems: list[Problem] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("TENANT_SHAPE", where, "each quota must be an object",
                                    "NN-12"))
            continue
        qid = str(entry.get("id"))
        scope = f"{where}#{qid}"
        budget.check(scope)
        problems += expect(qid not in seen, "TENANT_QUOTA_DUPLICATE", scope,
                           f"quota '{qid}' declared twice", "NN-12")
        seen.add(qid)
        problems += expect(entry.get("scope") in QUOTA_SCOPES, "TENANT_QUOTA_SCOPE", scope,
                           f"quota scope must be one of {sorted(QUOTA_SCOPES)}", "NN-06")
        default = int(entry.get("default") or 0)
        ceiling = int(entry.get("hard_ceiling") or 0)
        problems += expect(default > 0, "TENANT_QUOTA_DEFAULT", scope,
                           "a quota needs a positive default", "NN-06")
        problems += expect(ceiling >= default, "TENANT_QUOTA_CEILING", scope,
                           f"the hard ceiling ({ceiling}) must not be below the default "
                           f"({default}); a ceiling that can be raised without limit is not a "
                           f"ceiling", "NN-06")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "TENANT_QUOTA_NOTES", scope,
                           "say what this quota protects", "NN-06")
    return problems


def _offboarding(model: dict, where: str) -> list[Problem]:
    offboarding = model.get("offboarding")
    if not isinstance(offboarding, dict):
        return [Problem("TENANT_SHAPE", where, "offboarding must be an object", "NN-06")]
    problems = list(expect(offboarding.get("settlement_must_complete_first") is True,
                           "TENANT_CLOSE_BEFORE_SETTLEMENT", where,
                           "settlement must complete before the key is destroyed", "NN-06"))
    problems += expect(offboarding.get("kek_destruction_required") is True,
                       "TENANT_CLOSE_WITHOUT_SHREDDING", where,
                       "offboarding must destroy the tenant key", "NN-06")
    problems += expect(offboarding.get("ledger_retained") is True, "TENANT_LEDGER_NOT_RETAINED",
                       where,
                       "the ledger must survive offboarding; it records what the platform did, "
                       "not only what the tenant owned", "NN-13")
    problems += expect(offboarding.get("audit_retained") is True, "TENANT_AUDIT_NOT_RETAINED",
                       where, "audit records must survive offboarding", "NN-13")
    grace = int(offboarding.get("grace_period_days") or 0)
    problems += expect(0 < grace <= 180, "TENANT_NO_GRACE_PERIOD", where,
                       f"a bounded grace period is required before destruction, got {grace} days",
                       "NN-06")
    return problems


def _audit_binding(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    event_class = str(model.get("audit_event_class") or "")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    return list(expect(event_class in classes, "TENANT_AUDIT_CLASS_UNKNOWN", where,
                       f"lifecycle changes are recorded as '{event_class}', which "
                       f"governance/audit-log.json does not define", "NN-13"))


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .tenantsgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("TENANT_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("TENANT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/tenant-registry.json "
                                    f"but does not exist; run scripts/render-tenants.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("TENANT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the registry generates", "NN-12"))
    return problems
