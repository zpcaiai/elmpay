"""B14 — service decomposition, runtime dependencies and failure isolation.

B00's module registry says which modules exist and which may depend on which.
That is a *build-time* statement. This is the runtime one: which calls are
synchronous, how long they may take, what happens when they fail, and which of
them are allowed to be on the money path at all.

The rules encode the ways a service split goes wrong:

* a synchronous cycle means two services cannot be deployed, scaled or recovered
  independently -- they are one service wearing two names;
* a caller whose budget is smaller than the sum of its synchronous timeouts has
  decorative timeouts: what actually fires is the *upstream* deadline, and the
  work is abandoned mid-flight;
* a service reaching into another service's tables is a distributed monolith
  with none of a monolith's transactional guarantees;
* retrying a non-idempotent call is how one timeout becomes two charges (NN-04);
* on the money path, "the dependency is down so we let it through" is how a
  platform pays for goods it never charged for -- except for the provider call
  itself, where the honest answer is ``unknown``, never ``failed`` (AC-01).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

TOPOLOGY = Path("governance/service-topology.json")
MODULES = Path("governance/module-registry.json")
EVENTS = Path("governance/event-catalog.json")
DATA = Path("governance/data-architecture.json")
DOMAIN = Path("governance/domain-model.json")
SCHEMA = Path("contracts/sql/schema.sql")

NAME = re.compile(r"^[a-z][a-z0-9-]*$")
CREATE_TABLE = re.compile(r"^CREATE TABLE IF NOT EXISTS ([a-z_][a-z0-9_]*) [(]$")
FOREIGN_KEY = re.compile(r"FOREIGN KEY [(]([a-z_]+)[)] REFERENCES ([a-z_]+)")
MONEY_PATH_TIERS = {"tier1"}
CONNECTOR_LAYER = "connector"
FAILURE_MODES = {"fail_closed", "degrade", "fail_open"}
CONNECTOR_OPERATIONS = {"mutating", "query"}


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("service-topology", "B14")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(TOPOLOGY)
    budget.check(where)
    try:
        topology = load_json(root / TOPOLOGY)
    except Exception as exc:
        return [Problem("TOPO_UNREADABLE", where,
                        f"cannot read the service topology: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(topology.get("schema_version", ""))),
                       "TOPO_VERSION_FIELD", where, "schema_version must be semver", "NN-12")

    services = topology.get("services")
    if not isinstance(services, list) or not services:
        return problems + [Problem("TOPO_SHAPE", where, "'services' must be a non-empty list",
                                   "NN-12")]

    problems += _policy(topology, where)

    modules = _modules(root)
    events = _events(root)
    tables_by_owner = _tables(root)
    call_kinds = set(topology.get("call_kinds") or [])
    external_dependencies = set(topology.get("external_dependencies") or [])
    tiers = set(topology.get("criticality_tiers") or [])
    runtimes = set(topology.get("runtime_kinds") or [])

    by_name: dict = {}
    seen: set = set()
    for index, service in enumerate(services):
        problems += _service(service, f"{where}#{index}", topology, modules, events,
                             call_kinds, external_dependencies, tiers, runtimes, seen,
                             by_name, budget)

    for module, entry in sorted(modules.items()):
        if entry.get("layer") in ("service", "app"):
            problems += expect(module in seen, "TOPO_SERVICE_MISSING", where,
                               f"module '{module}' is a deployable {entry['layer']} but has no "
                               f"topology entry; an undeclared service has no timeout, no "
                               f"failure mode and no owner at 3am", "NN-12")

    problems += _cycles(by_name, where)
    problems += _budgets(by_name, topology, where)
    problems += _depth(by_name, topology, where)
    problems += _database_isolation(by_name, tables_by_owner, where)
    problems += _foreign_keys(root, where)
    problems += _generated(root, budget)
    return problems


def _policy(topology: dict, where: str) -> list[Problem]:
    policy = topology.get("policy") or {}
    problems = list(expect(0 < int(policy.get("max_sync_depth") or 0) <= 5, "TOPO_POLICY", where,
                           "a maximum synchronous depth must be declared and small; every extra "
                           "hop multiplies the failure probability of one request", "NN-12"))
    problems += expect(policy.get("money_path_failure_mode") == "fail_closed", "TOPO_POLICY",
                       where,
                       "the money path must fail closed; letting a payment through because a "
                       "dependency is down is how a platform ships goods it never charged for",
                       "NN-12")
    problems += expect(policy.get("database_access") == "exclusive_per_owner", "TOPO_POLICY",
                       where,
                       "each service must own its tables exclusively; shared tables are the "
                       "definition of a distributed monolith", "NN-01")
    problems += expect(len(str(policy.get("sync_budget_rule") or "")) >= 20, "TOPO_POLICY", where,
                       "the budget rule must be written down", "NN-12")
    return problems


def _modules(root: Path) -> dict:
    try:
        registry = load_json(root / MODULES)
    except Exception:
        return {}
    return {m["name"]: m for m in registry.get("modules", [])}


def _events(root: Path) -> dict:
    try:
        catalog = load_json(root / EVENTS)
    except Exception:
        return {"published": set(), "consumers": {}}
    published = {e["name"] for e in catalog.get("events", [])}
    producers = {e["name"]: e["producer"] for e in catalog.get("events", [])}
    consumers = {c["module"]: set(c.get("subscribes") or [])
                 for c in catalog.get("consumers", [])}
    return {"published": published, "producers": producers, "consumers": consumers}


def _tables(root: Path) -> dict:
    try:
        arch = load_json(root / DATA)
    except Exception:
        return {}
    out: dict = {}
    for table in arch.get("tables", []):
        out.setdefault(table.get("owner"), set()).add(table.get("table"))
    return out


def _service(service: Any, scope: str, topology: dict, modules: dict, events: dict,
             call_kinds: set, external_dependencies: set, tiers: set, runtimes: set,
             seen: set, by_name: dict, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(service, dict):
        return [Problem("TOPO_SHAPE", scope, "each service must be an object", "NN-12")]

    name = service.get("name")
    scope = f"{scope}:{name}"
    budget.check(scope)
    problems += expect(isinstance(name, str) and NAME.match(name or ""), "TOPO_NAME", scope,
                       f"service name '{name}' must be kebab-case", "NN-12")
    problems += expect(name not in seen, "TOPO_DUPLICATE", scope,
                       f"duplicate service '{name}'", "NN-12")
    seen.add(name)
    by_name[name] = service

    module = service.get("module")
    problems += expect(module in modules, "TOPO_MODULE", scope,
                       f"'{module}' is not a registered module", "NN-01")
    if module in modules:
        problems += expect(modules[module].get("layer") in ("service", "app"), "TOPO_MODULE",
                           scope,
                           f"'{module}' is a {modules[module].get('layer')}; only services and "
                           f"apps are deployable units", "NN-01")

    problems += expect(service.get("runtime") in runtimes, "TOPO_RUNTIME", scope,
                       f"runtime kind '{service.get('runtime')}' is not declared", "NN-12")
    problems += expect(service.get("criticality") in tiers, "TOPO_CRITICALITY", scope,
                       f"criticality '{service.get('criticality')}' is not a declared tier",
                       "NN-12")
    problems += expect(len(str(service.get("notes") or "")) >= 12, "TOPO_NOTES", scope,
                       "each service must record why its boundary is where it is", "NN-12")

    slo = service.get("slo") or {}
    problems += expect(bool(slo.get("availability")) and int(slo.get("p99_ms") or 0) > 0,
                       "TOPO_SLO", scope,
                       "a service must publish an availability target and a p99 latency; "
                       "a dependency with no stated latency cannot be given a timeout", "NN-12")

    request_budget = int(service.get("request_budget_ms") or 0)
    problems += expect(request_budget > 0, "TOPO_BUDGET", scope,
                       "a service must declare its own request budget", "NN-12")

    dependencies = service.get("dependencies")
    if not isinstance(dependencies, list):
        return problems + [Problem("TOPO_SHAPE", scope, "'dependencies' must be a list", "NN-12")]

    tier = service.get("criticality")
    for index, dependency in enumerate(dependencies):
        problems += _dependency(dependency, f"{scope}[{index}]", service, tier, modules,
                                call_kinds, external_dependencies, request_budget)

    # Events: what a service says it publishes must be what the catalogue says.
    producers = events.get("producers") or {}
    for name_ in service.get("publishes") or []:
        problems += expect(name_ in producers, "TOPO_EVENT_UNKNOWN", scope,
                           f"publishes '{name_}', which is not in the event catalogue", "NN-12")
        if name_ in producers:
            problems += expect(producers[name_] == module, "TOPO_EVENT_PRODUCER", scope,
                               f"claims to publish '{name_}' but the catalogue says "
                               f"'{producers[name_]}' produces it", "NN-01")
    declared_consumers = (events.get("consumers") or {}).get(module, set())
    for name_ in service.get("consumes") or []:
        problems += expect(name_ in (events.get("published") or set()), "TOPO_EVENT_UNKNOWN",
                           scope, f"consumes '{name_}', which is not in the event catalogue",
                           "NN-12")
        problems += expect(name_ in declared_consumers, "TOPO_EVENT_SUBSCRIPTION", scope,
                           f"consumes '{name_}' but the event catalogue does not list "
                           f"'{module}' as a subscriber", "NN-12")
    return problems


def _dependency(dependency: Any, scope: str, service: dict, tier: str, modules: dict,
                call_kinds: set, external_dependencies: set, request_budget: int) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(dependency, dict):
        return [Problem("TOPO_SHAPE", scope, "each dependency must be an object", "NN-12")]

    target = dependency.get("target")
    is_external = target in external_dependencies
    problems += expect(target in modules or is_external, "TOPO_DEP_UNKNOWN", scope,
                       f"depends on '{target}', which is not a registered module", "NN-01")
    if not is_external:
        declared = set((modules.get(service.get("module")) or {}).get("depends_on") or [])
        problems += expect(target in declared, "TOPO_DEP_UNDECLARED", scope,
                           f"'{service.get('module')}' calls '{target}' at runtime but the module "
                           f"registry does not list it as a dependency; a runtime edge the build "
                           f"does not know about cannot be enforced", "NN-01")

    kind = dependency.get("kind")
    problems += expect(kind in call_kinds, "TOPO_CALL_KIND", scope,
                       f"call kind '{kind}' is not declared", "NN-12")
    problems += expect(len(str(dependency.get("reason") or "")) >= 6, "TOPO_DEP_REASON", scope,
                       "every runtime dependency must say what it is for", "NN-12")
    problems += expect(len(str(dependency.get("degradation") or "")) >= 8, "TOPO_DEGRADATION",
                       scope,
                       f"'{service.get('name')}' must state what happens when '{target}' is "
                       f"down; an undeclared failure mode is decided by whoever is on call",
                       "NN-12")

    if kind != "sync":
        return problems

    timeout = int(dependency.get("timeout_ms") or 0)
    problems += expect(timeout > 0, "TOPO_TIMEOUT", scope,
                       "a synchronous dependency must declare a timeout; the default is "
                       "'forever', and forever is how a thread pool dies", "NN-12")
    problems += expect(timeout <= request_budget, "TOPO_TIMEOUT_BUDGET", scope,
                       f"the timeout on '{target}' ({timeout}ms) exceeds the caller's own budget "
                       f"({request_budget}ms); the timeout would never fire", "NN-12")

    retries = dependency.get("retries")
    problems += expect(isinstance(retries, int) and 0 <= retries <= 3, "TOPO_RETRY", scope,
                       "retries must be declared and small", "NN-04")

    breaker = dependency.get("circuit_breaker") or {}
    problems += expect(bool(breaker), "TOPO_CIRCUIT_BREAKER", scope,
                       f"a synchronous call to '{target}' needs a circuit breaker; without one a "
                       f"slow dependency becomes a queue and the queue becomes an outage",
                       "NN-12")
    if breaker:
        problems += expect(0 < int(breaker.get("error_rate_threshold_pct") or 0) <= 100,
                           "TOPO_CIRCUIT_BREAKER", scope,
                           "the breaker needs an error-rate threshold", "NN-12")
        problems += expect(int(breaker.get("open_seconds") or 0) > 0, "TOPO_CIRCUIT_BREAKER",
                           scope, "the breaker needs a cool-down", "NN-12")

    bulkhead = dependency.get("bulkhead") or {}
    problems += expect(int(bulkhead.get("max_concurrent") or 0) > 0, "TOPO_BULKHEAD", scope,
                       f"a synchronous call to '{target}' needs a concurrency bulkhead; one slow "
                       f"dependency must not be able to consume every worker", "NN-12")

    # Failure mode is a declared enum, not a phrase to be pattern-matched. Reading
    # intent out of prose gets "不放行" wrong, and a control that misreads its own
    # input is worse than no control.
    failure_mode = dependency.get("failure_mode")
    problems += expect(failure_mode in FAILURE_MODES, "TOPO_FAILURE_MODE", scope,
                       f"failure_mode '{failure_mode}' must be one of {sorted(FAILURE_MODES)}",
                       "NN-12")

    layer = (modules.get(target) or {}).get("layer")
    if layer == CONNECTOR_LAYER:
        operation = dependency.get("operation")
        problems += expect(operation in CONNECTOR_OPERATIONS, "TOPO_CONNECTOR_OPERATION", scope,
                           f"a connector call must say whether it is 'mutating' (authorise, "
                           f"capture, refund) or a read-only 'query'; the retry rules are "
                           f"opposite for the two", "NN-04")
        if operation == "mutating":
            problems += expect(retries == 0, "TOPO_CONNECTOR_RETRY", scope,
                               f"'{target}' is a payment connector and this call moves money; "
                               f"retrying it on timeout is how one payment becomes two. Retry "
                               f"belongs to the caller with an idempotency key, not to the "
                               f"transport", "NN-04")
            problems += expect("unknown" in str(dependency.get("degradation") or ""),
                               "TOPO_CONNECTOR_DEGRADATION", scope,
                               f"when '{target}' is unavailable the attempt must become "
                               f"'unknown', not 'failed'; treating a timeout as a decline is "
                               f"what makes the customer pay twice (AC-01)", "NN-03")
            problems += expect(failure_mode == "degrade", "TOPO_FAILURE_MODE", scope,
                               f"a mutating connector call must degrade to 'unknown' rather than "
                               f"fail closed or open; the platform genuinely does not know",
                               "NN-03")
    elif tier in MONEY_PATH_TIERS:
        problems += expect(failure_mode == "fail_closed", "TOPO_FAIL_OPEN", scope,
                           f"'{target}' is a tier-1 dependency on the money path but this call "
                           f"is declared '{failure_mode}'; letting requests through while it is "
                           f"down is how a platform ships goods it never charged for", "NN-12")
    return problems


def _deps(service: Any) -> list:
    """Well-formed dependencies only.

    Malformed entries are already reported by _service; the graph analyses must
    skip them rather than crash, because a gate that dies on bad input tells you
    nothing about the rest of the file.
    """
    if not isinstance(service, dict):
        return []
    raw = service.get("dependencies")
    return [d for d in raw if isinstance(d, dict)] if isinstance(raw, list) else []


def _cycles(by_name: dict, where: str) -> list[Problem]:
    """A synchronous cycle is two services pretending to be independent."""
    edges = {name: {d["target"] for d in _deps(service)
                    if d.get("kind") == "sync" and d.get("target") in by_name}
             for name, service in by_name.items()}
    problems: list[Problem] = []
    seen_cycles: set = set()

    def walk(node: str, path: list) -> None:
        for nxt in sorted(edges.get(node, ())):
            if nxt in path:
                cycle = path[path.index(nxt):] + [nxt]
                key = tuple(sorted(set(cycle)))
                if key not in seen_cycles:
                    seen_cycles.add(key)
                    problems.append(Problem(
                        "TOPO_SYNC_CYCLE", where,
                        f"synchronous dependency cycle {' -> '.join(cycle)}; services in a "
                        f"synchronous cycle cannot be deployed, scaled or recovered "
                        f"independently, which means they are one service with two names",
                        "NN-01"))
                continue
            walk(nxt, path + [nxt])

    for name in sorted(edges):
        walk(name, [name])
    return problems


def _budgets(by_name: dict, topology: dict, where: str) -> list[Problem]:
    """A caller's budget must cover the sum of its synchronous timeouts."""
    problems: list[Problem] = []
    for name, service in sorted(by_name.items()):
        if not isinstance(service, dict):
            continue
        # Dependencies in the same exclusive group are alternatives -- a request
        # uses one provider, not all five -- so the group contributes its worst
        # case once. Summing them would force absurd budgets and push people to
        # delete the timeouts instead.
        ungrouped, groups = 0, {}
        for dependency in _deps(service):
            if dependency.get("kind") != "sync":
                continue
            timeout = int(dependency.get("timeout_ms") or 0)
            group = dependency.get("exclusive_group")
            if group:
                groups[group] = max(groups.get(group, 0), timeout)
            else:
                ungrouped += timeout
        total = ungrouped + sum(groups.values())
        request_budget = int(service.get("request_budget_ms") or 0)
        problems += expect(total <= request_budget, "TOPO_BUDGET_EXCEEDED", f"{where}:{name}",
                           f"the synchronous timeouts of '{name}' add up to {total}ms but its "
                           f"request budget is {request_budget}ms; in the worst case the caller "
                           f"upstream gives up first and the work is abandoned mid-flight",
                           "NN-12")
        for dependency in _deps(service):
            if dependency.get("kind") != "sync":
                continue
            callee = by_name.get(dependency.get("target"))
            if not callee:
                continue
            callee_budget = int(callee.get("request_budget_ms") or 0)
            problems += expect(int(dependency.get("timeout_ms") or 0) >= callee_budget,
                               "TOPO_TIMEOUT_TOO_TIGHT", f"{where}:{name}",
                               f"'{name}' allows {dependency.get('timeout_ms')}ms for "
                               f"'{dependency.get('target')}', which itself budgets "
                               f"{callee_budget}ms; the caller would abandon work the callee is "
                               f"still legitimately doing, and retry it", "NN-04")
    return problems


def _depth(by_name: dict, topology: dict, where: str) -> list[Problem]:
    limit = int((topology.get("policy") or {}).get("max_sync_depth") or 0)
    if limit <= 0:
        return []
    edges = {name: [d["target"] for d in _deps(service)
                    if d.get("kind") == "sync" and d.get("target") in by_name]
             for name, service in by_name.items()}
    problems: list[Problem] = []
    worst: dict = {}

    def depth(node: str, path: tuple) -> int:
        if node in path:
            return len(path)
        best = len(path)
        for nxt in edges.get(node, ()):
            best = max(best, depth(nxt, path + (node,)))
        return best

    for name in sorted(edges):
        worst[name] = depth(name, ())
    for name, value in sorted(worst.items()):
        problems += expect(value <= limit, "TOPO_SYNC_DEPTH", f"{where}:{name}",
                           f"the synchronous call chain starting at '{name}' is {value} hops "
                           f"deep, over the declared limit of {limit}; each hop multiplies the "
                           f"chance that one request fails for a reason nobody can see",
                           "NN-12")
    return problems


def _database_isolation(by_name: dict, tables_by_owner: dict, where: str) -> list[Problem]:
    """A service may read and write only the tables its module owns."""
    problems: list[Problem] = []
    for name, service in sorted(by_name.items()):
        if not isinstance(service, dict):
            continue
        module = service.get("module")
        for table in service.get("reads_tables") or []:
            owner = next((o for o, ts in tables_by_owner.items() if table in ts), None)
            problems += expect(owner == module, "TOPO_TABLE_ACCESS", f"{where}:{name}",
                               f"'{name}' reads '{table}', which belongs to '{owner}'; reaching "
                               f"into another service's tables is a distributed monolith with "
                               f"none of a monolith's transactional guarantees", "NN-01")
    return problems


def _foreign_keys(root: Path, where: str) -> list[Problem]:
    """The gap B13 left open, checked against the DDL rather than the intent.

    Reading the generated schema instead of the domain model matters: what breaks
    a service split is the constraint that actually reaches the database, not the
    reference recorded in a JSON file.
    """
    schema = root / SCHEMA
    if not schema.is_file():
        return [Problem("TOPO_SCHEMA_MISSING", str(SCHEMA),
                        "the generated schema is missing, so cross-module foreign keys cannot "
                        "be checked; run scripts/render-domain.py", "NN-12")]
    try:
        arch = load_json(root / DATA)
    except Exception:
        return []
    owner_of = {t.get("table"): t.get("owner") for t in arch.get("tables", [])}

    problems: list[Problem] = []
    current = None
    for line in schema.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        created = CREATE_TABLE.match(stripped)
        if created:
            current = created.group(1)
            continue
        match = FOREIGN_KEY.search(stripped)
        if not (match and current):
            continue
        column, target = match.group(1), match.group(2)
        source_owner, target_owner = owner_of.get(current), owner_of.get(target)
        if source_owner and target_owner and source_owner != target_owner:
            problems.append(Problem(
                "TOPO_FOREIGN_KEY_CROSS_MODULE", str(SCHEMA),
                f"the generated schema creates a foreign key from '{current}.{column}' "
                f"(owned by '{source_owner}') to '{target}' (owned by '{target_owner}'); a "
                f"database-level constraint across an ownership boundary makes the two services "
                f"impossible to migrate, deploy or shard apart -- keep the column, drop the "
                f"constraint, and validate in the owning service", "NN-01"))
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .topogen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("TOPO_GENERATED_MISSING", rel,
                                    "generated topology artefact is missing; run "
                                    "scripts/render-topology.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("TOPO_GENERATED", rel,
                                    f"the artefact cannot be derived from the topology: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("TOPO_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the topology; run "
                                    "scripts/render-topology.py", "NN-12"))
    return problems
