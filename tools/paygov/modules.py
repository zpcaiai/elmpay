"""B00 — module registry validation.

Enforces the structural rules that make the monolith-first deployment
splittable later (charter §3):

* one owner per module, no unowned code;
* exclusive table ownership — two modules may never claim the same table;
* a strict layer order lib < connector < service < app;
* an acyclic dependency graph;
* connectors are leaves: they may not reach services, apps or any database;
* every module declares an SLO, threats and a migration strategy.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

REGISTRY_PATH = Path("governance/module-registry.json")
REQUIRED_FIELDS = ("name", "layer", "path", "owner", "owned_tables", "depends_on",
                   "inbound", "outbound", "slo", "threats", "migration")
# Tables that belong to the business projects and must never be owned here (NN-01).
FORBIDDEN_TABLE_PREFIXES = ("business_order", "order_item", "inventory", "product", "shipment")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("module-registry", "B00")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    where = str(REGISTRY_PATH)
    try:
        registry: Any = load_json(root / REGISTRY_PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("MODULE_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(registry.get("schema_version", "")))),
                       "MODULE_VERSION", where, "schema_version must be semantic version", "NN-12")

    layers = registry.get("layers")
    modules = registry.get("modules")
    if not isinstance(layers, dict) or not isinstance(modules, list):
        return problems + [Problem("MODULE_SHAPE", where,
                                   "registry needs 'layers' object and 'modules' array", "NN-12")]

    by_name: dict[str, dict] = {}
    table_owner: dict[str, str] = {}

    for index, module in enumerate(modules):
        scope = f"{where}#modules[{index}]"
        if not isinstance(module, dict):
            problems.append(Problem("MODULE_SHAPE", scope, "module must be an object", "NN-12"))
            continue
        missing = [f for f in REQUIRED_FIELDS if f not in module]
        if missing:
            problems.append(Problem("MODULE_SHAPE", scope, f"missing fields {missing}", "NN-12"))
            continue
        name = module["name"]
        scope = f"{where}#{name}"
        if name in by_name:
            problems.append(Problem("MODULE_DUPLICATE", scope, f"duplicate module '{name}'", "NN-12"))
            continue
        by_name[name] = module

        problems += expect(module["layer"] in layers, "MODULE_LAYER", scope,
                           f"unknown layer '{module['layer']}'", "NN-12")
        problems += expect(bool(str(module["owner"]).strip()), "MODULE_OWNER", scope,
                           "module must declare an owner", "NN-11")
        problems += expect((root / module["path"]).is_dir(), "MODULE_PATH", scope,
                           f"declared path '{module['path']}' does not exist", "NN-12")
        problems += expect(isinstance(module["slo"], dict) and bool(module["slo"]),
                           "MODULE_SLO", scope, "module must declare an SLO", "NN-12")
        problems += expect(isinstance(module["threats"], list) and bool(module["threats"]),
                           "MODULE_THREATS", scope, "module must declare at least one threat", "NN-12")
        problems += expect(bool(str(module["migration"]).strip()), "MODULE_MIGRATION", scope,
                           "module must declare a migration strategy", "NN-12")

        for table in module["owned_tables"]:
            if table in table_owner:
                problems.append(Problem("MODULE_TABLE_CONFLICT", scope,
                                        f"table '{table}' is already owned by '{table_owner[table]}'",
                                        "NN-09"))
            table_owner[table] = name
            for prefix in FORBIDDEN_TABLE_PREFIXES:
                if table.startswith(prefix):
                    problems.append(Problem("MODULE_BUSINESS_TABLE", scope,
                                            f"'{table}' is business-order data and must stay in the "
                                            f"originating project", "NN-01"))
        if module["layer"] == "connector":
            problems += expect(not module["owned_tables"], "MODULE_CONNECTOR_DB", scope,
                               "connectors must not own database tables", "NN-01")

    problems += _dependencies(by_name, layers, where)
    problems += _acyclic(by_name, where)
    return problems


def _dependencies(by_name: dict[str, dict], layers: dict, where: str) -> list[Problem]:
    problems: list[Problem] = []
    for name, module in by_name.items():
        scope = f"{where}#{name}"
        allowed = set(layers.get(module["layer"], {}).get("may_depend_on", []))
        for dep in module["depends_on"]:
            if dep not in by_name:
                problems.append(Problem("MODULE_DEP_UNKNOWN", scope,
                                        f"depends on unknown module '{dep}'", "NN-12"))
                continue
            dep_layer = by_name[dep]["layer"]
            if dep_layer not in allowed:
                problems.append(Problem("MODULE_DEP_LAYER", scope,
                                        f"layer '{module['layer']}' may not depend on layer "
                                        f"'{dep_layer}' (module '{dep}')", "NN-01"))
            if dep == name:
                problems.append(Problem("MODULE_DEP_SELF", scope, "module depends on itself", "NN-12"))
    return problems


def _acyclic(by_name: dict[str, dict], where: str) -> list[Problem]:
    """Iterative DFS; reports the first cycle found per entry point."""
    WHITE, GREY, BLACK = 0, 1, 2
    colour = {name: WHITE for name in by_name}
    problems: list[Problem] = []

    for start in sorted(by_name):
        if colour[start] != WHITE:
            continue
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        colour[start] = GREY
        while stack:
            node, path = stack[-1]
            pending = [d for d in by_name[node]["depends_on"]
                       if d in by_name and colour.get(d) != BLACK]
            progressed = False
            for dep in pending:
                if colour[dep] == GREY:
                    problems.append(Problem("MODULE_DEP_CYCLE", f"{where}#{node}",
                                            "dependency cycle: " + " -> ".join(path + [dep]), "NN-01"))
                    colour[dep] = BLACK
                    continue
                colour[dep] = GREY
                stack.append((dep, path + [dep]))
                progressed = True
                break
            if not progressed:
                colour[node] = BLACK
                stack.pop()
    return problems
