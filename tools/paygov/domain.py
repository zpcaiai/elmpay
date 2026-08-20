"""B08 — payment domain model and ubiquitous language gate.

The model in ``governance/domain-model.json`` is normative and
language-neutral: Java records, SQL DDL and API schemas are generated from it,
so a field that exists only in one of those is a defect rather than a detail.

The rules encode the programme's non-negotiables where they are cheapest to
enforce — in the type system:

* no monetary field may use a floating-point or unconstrained numeric type;
* every entity a module owns must be a table that module actually owns in
  ``governance/module-registry.json``;
* every tenant-scoped entity must carry ``tenant_id``;
* every entity, state and concept must be in the glossary, so the same idea has
  one name in code, contracts, dashboards and runbooks.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import catalogue
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

MODEL = Path("governance/domain-model.json")
GLOSSARY = Path("governance/glossary.json")
REGISTRY = Path("governance/module-registry.json")

ENTITY_NAME = re.compile(r"^[A-Z][A-Za-z0-9]+$")
FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
MONEY_FIELD = re.compile(r"(amount|price|fee|balance|total)")
# Business-order concepts belong to the originating project (NN-01).
FORBIDDEN_FIELDS = ("sku", "item", "quantity", "inventory", "stock", "shipping_address",
                    "product_name", "fulfilment", "fulfillment")
IDENTITY_SUFFIX = "_id"


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("domain-model", "B08")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget(seconds=60).start()
    where = str(MODEL)
    try:
        model: Any = load_json(root / MODEL, budget)
        glossary: Any = load_json(root / GLOSSARY, budget)
        registry: Any = load_json(root / REGISTRY, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("DOMAIN_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(model.get("schema_version", "")))),
                       "DOMAIN_VERSION", where, "schema_version must be semantic version", "NN-12")

    entities = model.get("entities")
    types = set(model.get("type_system", []))
    forbidden_types = set(model.get("forbidden_types", []))
    if not isinstance(entities, list) or not entities or not types:
        return problems + [Problem("DOMAIN_SHAPE", where,
                                   "model needs 'entities' and 'type_system'", "NN-12")]

    tables_by_module = {m["name"]: set(m["owned_tables"]) for m in registry["modules"]}
    known_modules = catalogue.module_names(str(root))
    names = {e.get("name") for e in entities}
    glossed = {t.get("term_en") for t in glossary.get("terms", [])}

    seen_tables: dict[str, str] = {}
    for entity in entities:
        name = entity.get("name", "?")
        scope = f"{where}#{name}"
        problems += expect(bool(ENTITY_NAME.match(str(name))), "DOMAIN_NAME", scope,
                           "entity names are PascalCase", "NN-12")
        problems += expect(len(str(entity.get("purpose", "")).strip()) >= 8, "DOMAIN_PURPOSE",
                           scope, "every entity must state what it is for", "NN-12")
        problems += expect(bool(entity.get("invariants")), "DOMAIN_INVARIANT", scope,
                           "an entity without invariants cannot be validated at runtime", "NN-12")

        module = entity.get("module")
        table = entity.get("table")
        problems += expect(module in known_modules, "DOMAIN_MODULE", scope,
                           f"unknown owning module '{module}'", "NN-12")
        problems += expect(bool(TABLE_NAME.match(str(table))), "DOMAIN_TABLE", scope,
                           "table names are snake_case", "NN-12")
        if table in seen_tables:
            problems.append(Problem("DOMAIN_TABLE_CONFLICT", scope,
                                    f"table '{table}' is already used by '{seen_tables[table]}'",
                                    "NN-09"))
        seen_tables[str(table)] = str(name)
        if module in tables_by_module:
            problems += expect(table in tables_by_module[module], "DOMAIN_TABLE_OWNERSHIP", scope,
                               f"module '{module}' does not own table '{table}' in the module "
                               f"registry", "NN-01")

        problems += expect(name in glossed, "DOMAIN_GLOSSARY", scope,
                           f"entity '{name}' has no glossary term; the ubiquitous language must "
                           f"cover every entity", "NN-12")

        field_names = [f.get("name") for f in entity.get("fields", [])]
        problems += expect(bool(field_names), "DOMAIN_SHAPE", scope, "entity has no fields",
                           "NN-12")
        problems += expect(len(field_names) == len(set(field_names)), "DOMAIN_FIELD", scope,
                           "duplicate field names", "NN-12")
        if entity.get("tenant_scoped"):
            problems += expect("tenant_id" in field_names, "DOMAIN_TENANT_SCOPE", scope,
                               "a tenant-scoped entity must carry tenant_id (NN-09)", "NN-09")
        for identity in entity.get("identity", []):
            problems += expect(identity in field_names, "DOMAIN_IDENTITY", scope,
                               f"identity field '{identity}' is not declared", "NN-12")

        for field in entity.get("fields", []):
            problems += _field(field, scope, types, forbidden_types, names)

        state_field = next((f for f in entity.get("fields", []) if f.get("name") == "state"), None)
        for state in entity.get("states", []):
            problems += expect(state in glossed, "DOMAIN_GLOSSARY", scope,
                               f"state '{state}' has no glossary term", "NN-12")
            if state_field is not None:
                problems += expect(state in state_field.get("enum", []), "DOMAIN_STATE", scope,
                                   f"declared state '{state}' is not a value of the state field",
                                   "NN-12")
    problems += _glossary(glossary, str(GLOSSARY))
    return problems


def _field(field: dict, scope: str, types: set[str], forbidden_types: set[str],
           entity_names: set[str]) -> list[Problem]:
    name = field.get("name", "?")
    where = f"{scope}.{name}"
    problems: list[Problem] = []
    problems += expect(bool(FIELD_NAME.match(str(name))), "DOMAIN_FIELD", where,
                       "field names are snake_case", "NN-12")
    kind = field.get("type")
    problems += expect(kind in types, "DOMAIN_TYPE", where,
                       f"'{kind}' is not in the declared type system", "NN-12")
    problems += expect(kind not in forbidden_types, "DOMAIN_FORBIDDEN_TYPE", where,
                       f"'{kind}' may not carry domain data", "NN-05")
    if MONEY_FIELD.search(str(name)) and not str(name).endswith("_ref"):
        problems += expect(kind == "money_minor", "DOMAIN_MONEY_TYPE", where,
                           f"monetary field must use 'money_minor' (integer minor units), "
                           f"not '{kind}' (NN-05)", "NN-05")
    if kind == "enum":
        values = field.get("enum")
        problems += expect(isinstance(values, list) and bool(values), "DOMAIN_ENUM", where,
                           "enum fields must declare their values", "NN-12")
        for value in values or []:
            problems += expect(bool(FIELD_NAME.match(str(value))), "DOMAIN_ENUM", where,
                               f"enum value '{value}' must be snake_case", "NN-12")
    if kind == "reference":
        target = field.get("target")
        problems += expect(target in entity_names, "DOMAIN_REFERENCE", where,
                           f"reference target '{target}' is not an entity", "NN-12")
        problems += expect(str(name).endswith(IDENTITY_SUFFIX), "DOMAIN_REFERENCE", where,
                           "reference fields end with '_id'", "NN-12")
    for forbidden in FORBIDDEN_FIELDS:
        problems += expect(forbidden not in str(name), "DOMAIN_BUSINESS_FIELD", where,
                           f"'{name}' is business-order data and belongs to the originating "
                           f"project, not to the payment platform (NN-01)", "NN-01")
    return problems


def _glossary(glossary: dict, where: str) -> list[Problem]:
    terms = glossary.get("terms")
    if not isinstance(terms, list) or not terms:
        return [Problem("DOMAIN_GLOSSARY_SHAPE", where, "'terms' must be a non-empty array",
                        "NN-12")]
    problems: list[Problem] = []
    seen: set[str] = set()
    for term in terms:
        english = term.get("term_en", "?")
        scope = f"{where}#{english}"
        problems += expect(english not in seen, "DOMAIN_GLOSSARY_DUPLICATE", scope,
                           f"duplicate term '{english}'", "NN-12")
        seen.add(english)
        problems += expect(len(str(term.get("term_cn", "")).strip()) >= 2,
                           "DOMAIN_GLOSSARY_TERM", scope, "every term needs a Chinese name",
                           "NN-12")
        problems += expect(len(str(term.get("definition", "")).strip()) >= 10,
                           "DOMAIN_GLOSSARY_TERM", scope, "every term needs a definition",
                           "NN-12")
        problems += expect(term.get("kind") in {"entity", "state", "concept"},
                           "DOMAIN_GLOSSARY_KIND", scope,
                           "term kind must be entity, state or concept", "NN-12")
    return problems
