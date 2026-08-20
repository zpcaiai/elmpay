"""B13 — executable model of row-level security, as PostgreSQL applies it.

There is no database in this environment, so the DDL in ``contracts/sql/`` is a
contract rather than a tested migration. What *can* be tested without a database
is whether the rules the DDL encodes actually produce isolation — and whether the
two mistakes that make RLS decorative are caught:

* forgetting ``FORCE ROW LEVEL SECURITY``, which leaves the table owner exempt.
  Operational scripts run as the owner, so the exemption applies exactly when it
  matters most;
* setting no tenant on the session, which in PostgreSQL makes the predicate
  error rather than match everything -- modelled here as a refusal, because the
  alternative (treating "no tenant" as "all tenants") is how a cron job dumps
  the whole table.

This is a model of the semantics, not of PostgreSQL. It cannot prove the
generated DDL is syntactically valid; only a real database can, and that is
stated as a known gap in the batch plan.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class TenantNotSet(Exception):
    """No tenant on the session: refuse rather than return everything."""


class NotPermitted(Exception):
    """The operation is forbidden on this table for this role."""


@dataclass(frozen=True)
class Policy:
    name: str
    tenant_column: str = "tenant_id"
    force_for_owner: bool = True


@dataclass
class Table:
    name: str
    owner_role: str
    rows: list = field(default_factory=list)
    policy: Policy | None = None
    append_only: bool = False

    def _visible(self, role: str, tenant: str | None) -> list:
        if self.policy is None:
            return list(self.rows)
        exempt = role == self.owner_role and not self.policy.force_for_owner
        if exempt:
            # This is the bug the FORCE clause exists to prevent, reproduced
            # faithfully so a test can prove the gate is worth having.
            return list(self.rows)
        if role == "platform_break_glass":
            return list(self.rows)
        if tenant is None:
            raise TenantNotSet(
                f"{self.name}: no {self.policy.tenant_column} on the session; refusing rather "
                f"than returning every tenant's rows")
        return [r for r in self.rows if r.get(self.policy.tenant_column) == tenant]

    def select(self, role: str, tenant: str | None = None) -> list:
        return self._visible(role, tenant)

    def insert(self, role: str, row: dict, tenant: str | None = None) -> None:
        if self.policy is not None and role != "platform_break_glass":
            if tenant is None:
                raise TenantNotSet(f"{self.name}: cannot insert without a tenant on the session")
            if row.get(self.policy.tenant_column) != tenant:
                raise NotPermitted(
                    f"{self.name}: WITH CHECK rejects a row for tenant "
                    f"{row.get(self.policy.tenant_column)!r} on a session for {tenant!r}")
        self.rows.append(dict(row))

    def update(self, role: str, match: dict, changes: dict, tenant: str | None = None) -> int:
        if self.append_only:
            raise NotPermitted(f"{self.name} is append-only: UPDATE was revoked")
        touched = 0
        for row in self._visible(role, tenant):
            if all(row.get(k) == v for k, v in match.items()):
                row.update(changes)
                touched += 1
        return touched

    def delete(self, role: str, match: dict, tenant: str | None = None) -> int:
        if self.append_only:
            raise NotPermitted(f"{self.name} is append-only: DELETE was revoked")
        visible = self._visible(role, tenant)
        doomed = [r for r in visible if all(r.get(k) == v for k, v in match.items())]
        for row in doomed:
            self.rows.remove(row)
        return len(doomed)


def build(spec: dict, owner_role: str = "app_owner") -> Table:
    """Build a table model from one entry of governance/data-architecture.json."""
    rls = spec.get("rls") or {}
    policy = None
    if rls.get("enabled"):
        policy = Policy(name=rls["policy"], force_for_owner=bool(rls.get("force_for_owner")))
    return Table(name=spec["table"], owner_role=owner_role, policy=policy,
                 append_only=spec.get("mutability") == "append_only")
