"""B13 — table ownership, partitioning, tenancy, retention and archival.

B08 said which tables exist. This says who owns each one, who may read a row,
how it is partitioned, how long it lives and where it goes afterwards. Each rule
here corresponds to a way multi-tenant payment data actually leaks or rots:

* a tenant-scoped table without row-level security is one forgotten ``WHERE``
  clause away from a cross-tenant read (NN-09);
* RLS that is not ``FORCE``d does nothing the moment an operator runs a script
  as the table owner, which is exactly when it matters;
* a ledger row that can be updated is not a ledger (NN-06);
* an archive with no integrity manifest and no read path is a delete with extra
  steps;
* a table whose owner disagrees with the module registry has two owners, which
  means it has none (NN-01).

The architecture is data (``governance/data-architecture.json``); this is the
gate, and ``tools/paygov/datagen.py`` turns it into DDL and a review document.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

ARCH = Path("governance/data-architecture.json")
MODULES = Path("governance/module-registry.json")
DOMAIN = Path("governance/domain-model.json")
EVENTS = Path("governance/event-catalog.json")

IDENT = re.compile(r"^[a-z][a-z0-9_]*$")
FINANCIAL_FLOOR_DAYS = 2555
# Tables that record money *moving*. A balance holder (ledger_account) and an
# instruction with a lifecycle (settlement_instruction) are not in this set: they
# are state, not evidence. Anything else in the ledger family that stays mutable
# has to justify itself, so the narrowing cannot be used as a loophole.
MOVEMENT_TABLES = {"ledger_transaction", "ledger_entry", "fee_record"}
LEDGER_FAMILY = re.compile(r"^(ledger_|fee_|settlement_)")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("data-architecture", "B13")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(ARCH)
    budget.check(where)
    try:
        arch = load_json(root / ARCH)
    except Exception as exc:
        return [Problem("DATA_UNREADABLE", where,
                        f"cannot read the data architecture: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(arch.get("schema_version", ""))), "DATA_VERSION_FIELD",
                       where, "schema_version must be semver", "NN-12")

    tables = arch.get("tables")
    if not isinstance(tables, list) or not tables:
        return problems + [Problem("DATA_SHAPE", where, "'tables' must be a non-empty list",
                                   "NN-12")]

    problems += _tenancy(arch, where)
    problems += _archive_policy(arch, where)
    problems += _sharding(arch, where)

    owner_of, registered = _registry(root)
    tenant_scoped_entities = _entities(root)
    partition_kinds = set(arch.get("partition_kinds") or [])
    mutability_kinds = set(arch.get("mutability_kinds") or [])
    deletion_strategies = set(arch.get("deletion_strategies") or [])
    problems += expect({"none", "range"} <= partition_kinds, "DATA_SHAPE", where,
                       "partition_kinds must at least offer 'none' and 'range'", "NN-12")
    problems += expect({"mutable", "append_only"} <= mutability_kinds, "DATA_SHAPE", where,
                       "mutability_kinds must distinguish mutable from append_only", "NN-06")
    problems += expect(deletion_strategies, "DATA_SHAPE", where,
                       "deletion_strategies must be enumerated; a personal column with no "
                       "deletion story cannot honour a deletion request", "NN-14")

    seen: set = set()
    for index, table in enumerate(tables):
        problems += _table(table, f"{where}#{index}", arch, owner_of, tenant_scoped_entities,
                           partition_kinds, mutability_kinds, deletion_strategies, seen, budget)

    for name in sorted(registered):
        problems += expect(name in seen, "DATA_TABLE_UNSPECIFIED", where,
                           f"table '{name}' is owned by a module but has no data-architecture "
                           f"entry; an unspecified table has no tenancy, retention or archival "
                           f"story", "NN-09")

    problems += _eventing_tables(root, seen, owner_of, where)
    problems += _generated(root, budget)
    return problems


def _tenancy(arch: dict, where: str) -> list[Problem]:
    tenancy = arch.get("tenancy") or {}
    problems = list(expect(tenancy.get("tenant_column") == "tenant_id", "DATA_TENANCY", where,
                           "the tenant column must be named tenant_id everywhere; one table "
                           "spelling it differently is the one that leaks", "NN-09"))
    problems += expect(bool(tenancy.get("session_setting")), "DATA_TENANCY", where,
                       "row-level security needs a session setting to compare against", "NN-09")
    problems += expect(len(str(tenancy.get("policy") or "")) >= 20, "DATA_TENANCY", where,
                       "the tenancy model must be written down", "NN-09")
    hatch = tenancy.get("escape_hatch") or {}
    problems += expect(bool(hatch.get("role")), "DATA_BREAK_GLASS", where,
                       "cross-tenant access must have a named role; an isolation design with no "
                       "emergency path gets bypassed with superuser during the first incident",
                       "NN-11")
    problems += expect(hatch.get("requires_audit_event") is True, "DATA_BREAK_GLASS", where,
                       "break-glass access must emit an audit event", "NN-11")
    problems += expect(hatch.get("requires_second_approver") is True, "DATA_BREAK_GLASS", where,
                       "break-glass access must be four-eyes", "NN-11")
    problems += expect(0 < int(hatch.get("max_session_minutes") or 0) <= 240,
                       "DATA_BREAK_GLASS", where,
                       "break-glass sessions must expire, and within hours not days", "NN-11")
    return problems


def _archive_policy(arch: dict, where: str) -> list[Problem]:
    archive = arch.get("archive") or {}
    problems = list(expect(bool(archive.get("target_scheme")), "DATA_ARCHIVE_POLICY", where,
                           "the archive destination scheme must be declared", "NN-12"))
    problems += expect(bool(archive.get("integrity")), "DATA_ARCHIVE_POLICY", where,
                       "archives need an integrity manifest; an archive nobody can verify is a "
                       "delete with extra steps", "NN-06")
    problems += expect(len(str(archive.get("policy") or "")) >= 10, "DATA_ARCHIVE_POLICY", where,
                       "the archive policy must state that archives are readable back", "NN-12")
    return problems


def _sharding(arch: dict, where: str) -> list[Problem]:
    sharding = arch.get("sharding") or {}
    problems = list(expect(sharding.get("key") == "tenant_id", "DATA_SHARDING", where,
                           "the future shard key must be tenant_id; choosing it later means "
                           "rewriting every index instead of moving data", "NN-09"))
    problems += expect(len(str(sharding.get("policy") or "")) >= 10, "DATA_SHARDING", where,
                       "the sharding stance must be stated even when the answer is 'not yet'",
                       "NN-12")
    return problems


def _registry(root: Path) -> tuple[dict, set]:
    try:
        registry = load_json(root / MODULES)
    except Exception:
        return {}, set()
    owner_of = {t: m["name"] for m in registry.get("modules", [])
                for t in m.get("owned_tables", [])}
    return owner_of, set(owner_of)


def _entities(root: Path) -> dict:
    try:
        domain = load_json(root / DOMAIN)
    except Exception:
        return {}
    return {e["table"]: bool(e.get("tenant_scoped")) for e in domain.get("entities", [])}


def _table(table: Any, scope: str, arch: dict, owner_of: dict, entities: dict,
           partition_kinds: set, mutability_kinds: set, deletion_strategies: set,
           seen: set, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(table, dict):
        return [Problem("DATA_SHAPE", scope, "each table must be an object", "NN-12")]

    name = table.get("table")
    scope = f"{scope}:{name}"
    budget.check(scope)
    problems += expect(isinstance(name, str) and IDENT.match(name or ""), "DATA_TABLE_NAME",
                       scope, f"table name '{name}' must be snake_case", "NN-12")
    problems += expect(name not in seen, "DATA_TABLE_DUPLICATE", scope,
                       f"duplicate table '{name}'", "NN-12")
    seen.add(name)

    owner = table.get("owner")
    problems += expect(name in owner_of, "DATA_TABLE_UNKNOWN", scope,
                       f"'{name}' is not owned by any registered module", "NN-01")
    if name in owner_of:
        problems += expect(owner == owner_of[name], "DATA_OWNER", scope,
                           f"the data architecture says '{owner}' owns '{name}' but the module "
                           f"registry says '{owner_of[name]}'; a table with two owners has none",
                           "NN-01")

    tenant_scoped = table.get("tenant_scoped")
    problems += expect(isinstance(tenant_scoped, bool), "DATA_TENANT_FLAG", scope,
                       "tenant_scoped must be declared explicitly", "NN-09")
    if name in entities:
        problems += expect(tenant_scoped == entities[name], "DATA_TENANT_FLAG", scope,
                           f"tenant scoping disagrees with the domain model "
                           f"({tenant_scoped} vs {entities[name]})", "NN-09")

    rls = table.get("rls") or {}
    session_setting = str((arch.get("tenancy") or {}).get("session_setting") or "")
    if tenant_scoped:
        problems += expect(rls.get("enabled") is True, "DATA_RLS_MISSING", scope,
                           f"'{name}' holds tenant data with no row-level security; isolation "
                           f"then depends on every query author remembering a WHERE clause",
                           "NN-09")
        predicate = str(rls.get("predicate") or "")
        problems += expect("tenant_id" in predicate and session_setting in predicate,
                           "DATA_RLS_PREDICATE", scope,
                           f"the policy predicate must compare tenant_id against "
                           f"'{session_setting}'; got {predicate!r}", "NN-09")
        problems += expect(rls.get("force_for_owner") is True, "DATA_RLS_FORCE", scope,
                           "row-level security must be FORCEd: without it the table owner "
                           "bypasses the policy, and operational scripts run as the owner",
                           "NN-09")
        problems += expect(bool(rls.get("policy")), "DATA_RLS_MISSING", scope,
                           "the policy needs a name so it can be audited and dropped", "NN-09")
    else:
        problems += expect(rls.get("enabled") is False, "DATA_RLS_MISSING", scope,
                           "a table without tenant data must say so rather than leave RLS "
                           "ambiguous", "NN-09")
        problems += expect(len(str(rls.get("reason") or "")) >= 8, "DATA_RLS_EXEMPTION", scope,
                           "a table exempt from tenant isolation must justify the exemption; "
                           "unexplained exemptions multiply", "NN-09")

    mutability = table.get("mutability")
    problems += expect(mutability in mutability_kinds, "DATA_MUTABILITY", scope,
                       f"mutability '{mutability}' is not a declared kind", "NN-06")
    if name in MOVEMENT_TABLES:
        problems += expect(mutability == "append_only", "DATA_LEDGER_MUTABLE", scope,
                           f"'{name}' records money moving but is declared mutable; a ledger row "
                           f"that can be updated is not a ledger, it is a spreadsheet", "NN-06")
    elif LEDGER_FAMILY.match(str(name or "")) and mutability != "append_only":
        problems += expect(len(str(table.get("mutability_reason") or "")) >= 8,
                           "DATA_LEDGER_MUTABLE_UNJUSTIFIED", scope,
                           f"'{name}' is in the ledger family and stays mutable; say why in "
                           f"'mutability_reason' so the exemption is a decision rather than an "
                           f"oversight", "NN-06")

    partition = table.get("partition") or {}
    kind = partition.get("kind")
    problems += expect(kind in partition_kinds, "DATA_PARTITION", scope,
                       f"partition kind '{kind}' is not declared", "NN-12")
    problems += expect(len(str(partition.get("reason") or "")) >= 8, "DATA_PARTITION_REASON",
                       scope,
                       "every partitioning decision -- including 'none' -- must state why; "
                       "unexplained partitioning is unmaintainable", "NN-12")
    if kind in ("range", "hash"):
        problems += expect(IDENT.match(str(partition.get("key") or "")), "DATA_PARTITION", scope,
                           "a partitioned table needs a partition key column", "NN-12")
    if kind == "range":
        problems += expect(bool(partition.get("interval")), "DATA_PARTITION", scope,
                           "range partitioning needs an interval, otherwise archival cannot be "
                           "a DETACH", "NN-12")

    retention = table.get("retention") or {}
    hot = int(retention.get("hot_days") or 0)
    warm = int(retention.get("warm_days") or 0)
    cold = int(retention.get("cold_days") or 0)
    problems += expect(0 < hot <= warm <= cold, "DATA_RETENTION_ORDER", scope,
                       f"retention tiers must be non-decreasing and positive "
                       f"(hot={hot} warm={warm} cold={cold})", "NN-12")
    if LEDGER_FAMILY.match(str(name or "")) or name in ("payment_intent", "refund", "dispute",
                                                        "recon_run", "recon_exception"):
        problems += expect(cold >= FINANCIAL_FLOOR_DAYS, "DATA_RETENTION_FLOOR", scope,
                           f"'{name}' is financial evidence and must be retained for at least "
                           f"{FINANCIAL_FLOOR_DAYS} days; disputes and audits reach back years",
                           "NN-06")
    archive_after = int(retention.get("archive_after_days") or 0)
    if archive_after:
        problems += expect(bool(retention.get("archive_target")), "DATA_ARCHIVE_TARGET", scope,
                           "a table scheduled for archival must name where it goes", "NN-12")
        problems += expect(archive_after >= hot, "DATA_RETENTION_ORDER", scope,
                           "archiving before the hot window expires deletes live data", "NN-12")

    indexes = table.get("indexes")
    problems += expect(isinstance(indexes, list) and indexes, "DATA_INDEX", scope,
                       "every table must declare at least one index; an unindexed payment table "
                       "is an outage at the first month of traffic", "NN-12")
    for index in indexes or []:
        if not isinstance(index, dict):
            problems.append(Problem("DATA_SHAPE", scope, "each index must be an object", "NN-12"))
            continue
        problems += expect(IDENT.match(str(index.get("name") or "")), "DATA_INDEX", scope,
                           f"index name '{index.get('name')}' must be snake_case", "NN-12")
        problems += expect(bool(index.get("columns")), "DATA_INDEX", scope,
                           "an index needs columns", "NN-12")
    if tenant_scoped and isinstance(indexes, list):
        leads = any(isinstance(i, dict) and (i.get("columns") or [None])[0] == "tenant_id"
                    for i in indexes)
        problems += expect(leads, "DATA_INDEX_TENANT", scope,
                           "a tenant-scoped table needs an index leading with tenant_id; without "
                           "one every tenant's queries scan every tenant's rows, and the future "
                           "shard key is not usable", "NN-09")

    shard_key = table.get("shard_key")
    if tenant_scoped:
        problems += expect(isinstance(shard_key, list) and shard_key
                           and shard_key[0] == "tenant_id", "DATA_SHARD_KEY", scope,
                           "a tenant-scoped table's shard key must start with tenant_id", "NN-09")

    personal = table.get("personal_columns") or []
    if personal:
        problems += expect(table.get("deletion_strategy") in deletion_strategies,
                           "DATA_DELETION_STRATEGY", scope,
                           f"'{name}' holds personal columns {personal} but declares no valid "
                           f"deletion strategy; a deletion request cannot be honoured by "
                           f"improvisation", "NN-14")
    return problems


def _eventing_tables(root: Path, seen: set, owner_of: dict, where: str) -> list[Problem]:
    """The outbox and inbox B12 designed must actually exist and be owned."""
    try:
        catalog = load_json(root / EVENTS)
    except Exception:
        return []
    problems: list[Problem] = []
    for section in ("outbox", "inbox"):
        block = catalog.get(section) or {}
        table = block.get("table")
        if not table:
            continue
        problems += expect(table in seen, "DATA_EVENTING_TABLE", where,
                           f"the event catalogue's {section} uses table '{table}', which has no "
                           f"data-architecture entry; the pattern only works if the table is "
                           f"really there", "NN-04")
        declared_owner = block.get("owner")
        if table in owner_of and declared_owner:
            problems += expect(owner_of[table] == declared_owner, "DATA_EVENTING_OWNER", where,
                               f"the event catalogue says '{declared_owner}' owns '{table}' but "
                               f"the module registry says '{owner_of[table]}'", "NN-01")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .datagen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("DATA_GENERATED_MISSING", rel,
                                    "generated data artefact is missing; run "
                                    "scripts/render-data.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("DATA_GENERATED", rel,
                                    f"the artefact cannot be derived from the architecture: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("DATA_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the architecture; run "
                                    "scripts/render-data.py", "NN-12"))
    return problems
