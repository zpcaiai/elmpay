"""B08 — generate the PostgreSQL schema from the normative domain model.

The DDL is generated rather than hand-written so that the invariants stated in
``governance/domain-model.json`` become database constraints instead of good
intentions: tenant scoping is NOT NULL, monetary columns are BIGINT with a
positive CHECK, identity fields become primary keys and declared references
become foreign keys.

Nothing here can be executed in this environment (there is no PostgreSQL), so
the DDL is treated as a *contract*: B13 owns applying and testing it.
"""
from __future__ import annotations

from pathlib import Path

from .repo import Budget, load_json

MODEL = Path("governance/domain-model.json")
ARCH = Path("governance/data-architecture.json")
BANNER = ("-- GENERATED FILE — do not edit by hand.\n"
          "-- Source of truth: governance/domain-model.json\n"
          "-- Regenerate with: python3 scripts/render-domain.py\n")

SQL_TYPE = {
    "uuid": "uuid",
    "string": "text",
    "enum": "text",
    "money_minor": "bigint",
    "currency": "char(3)",
    "timestamp": "timestamptz",
    "boolean": "boolean",
    "int32": "integer",
    "int64": "bigint",
    "json": "jsonb",
    "bytes": "bytea",
    "reference": "uuid",
    "string_map": "jsonb",
}
MONEY_NON_NEGATIVE = ("captured_amount_minor", "refunded_amount_minor")


def _column(field: dict) -> str:
    sql_type = SQL_TYPE[field["type"]]
    parts = [f'    {field["name"]} {sql_type}']
    if not field.get("nullable"):
        parts.append("NOT NULL")
    return " ".join(parts)


def _checks(entity: dict) -> list[str]:
    checks: list[str] = []
    for field in entity["fields"]:
        name = field["name"]
        if field["type"] == "enum":
            values = ", ".join(f"'{v}'" for v in field["enum"])
            checks.append(f'    CONSTRAINT {entity["table"]}_{name}_enum '
                          f'CHECK ({name} IN ({values}))')
        if field["type"] == "money_minor":
            operator = ">=" if name in MONEY_NON_NEGATIVE else ">"
            nullable = field.get("nullable")
            condition = f"{name} {operator} 0"
            if nullable:
                condition = f"{name} IS NULL OR {condition}"
            checks.append(f'    CONSTRAINT {entity["table"]}_{name}_positive CHECK ({condition})')
        if field["type"] == "currency":
            nullable = field.get("nullable")
            condition = f"{name} ~ '^[A-Z]{{3}}$'"
            if nullable:
                condition = f"{name} IS NULL OR {condition}"
            checks.append(f'    CONSTRAINT {entity["table"]}_{name}_iso CHECK ({condition})')
    return checks


def _owner_map(root: Path) -> dict:
    """Table -> owning module, from the B13 data architecture (empty before B13)."""
    path = root / ARCH
    if not path.is_file():
        return {}
    try:
        arch = load_json(path)
    except Exception:
        return {}
    return {t.get("table"): t.get("owner") for t in arch.get("tables", [])}


def schema_sql(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / MODEL, budget)
    tables = {e["name"]: e["table"] for e in model["entities"]}
    owner_of = _owner_map(root)

    lines = [BANNER, "-- All monetary columns are BIGINT minor units (NN-05).",
             "-- Ledger entries are append-only; revocation of UPDATE/DELETE is granted in B72.",
             ""]
    for entity in model["entities"]:
        table = entity["table"]
        lines.append(f'-- {entity["name"]}: {entity["purpose"]}')
        lines.append(f"CREATE TABLE IF NOT EXISTS {table} (")
        body = [_column(field) for field in entity["fields"]]
        identity = ", ".join(entity["identity"])
        body.append(f"    CONSTRAINT {table}_pk PRIMARY KEY ({identity})")
        deferred: list[str] = []
        for field in entity["fields"]:
            if field["type"] != "reference":
                continue
            target = tables[field["target"]]
            if owner_of.get(table) and owner_of.get(target) \
                    and owner_of[table] != owner_of[target]:
                # A database-level foreign key across an ownership boundary makes
                # the two services impossible to deploy, migrate or shard apart.
                # The column stays; the constraint does not. The owning service
                # validates the reference (B14, TOPO_FOREIGN_KEY_CROSS_MODULE).
                deferred.append(
                    f'-- {table}.{field["name"]} -> {target}: 跨模块引用'
                    f'（{owner_of[table]} -> {owner_of[target]}），不建数据库外键；'
                    f'由 {owner_of[target]} 负责校验存在性。')
                continue
            body.append(f'    CONSTRAINT {table}_{field["name"]}_fk '
                        f'FOREIGN KEY ({field["name"]}) REFERENCES {target} (id)')
        body += _checks(entity)
        lines.append(",\n".join(body))
        lines.append(");")
        lines += deferred
        if entity.get("tenant_scoped"):
            lines.append(f"CREATE INDEX IF NOT EXISTS {table}_tenant_idx ON {table} (tenant_id);")
            lines.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        lines.append("")

    lines += ["-- Invariants that cannot be expressed as column constraints are listed here",
              "-- and are enforced by the owning service plus property tests.", ""]
    for entity in model["entities"]:
        for invariant in entity["invariants"]:
            lines.append(f'--   [{entity["table"]}] {invariant}')
    return "\n".join(lines).rstrip() + "\n"


TARGETS = {"contracts/sql/schema.sql": schema_sql}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
